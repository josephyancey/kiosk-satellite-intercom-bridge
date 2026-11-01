package dev.yancey.intercombridge;

import java.io.Closeable;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.XECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Runs on a desktop JVM: java -ea dev.yancey.intercombridge.BridgeTest */
public final class BridgeTest {
    static final String KEY = "fleet-key", WORD = "house word";
    static final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });

    public static void main(String[] args) throws Exception {
        crypto();
        noise();
        auth();
        kioskCallsEcho();
        echoCallsKiosk();
        echoAnnouncesToKiosk();
        oneBridgeAtATime();
        System.out.println("BridgeTest: all passed");
        System.exit(0);
    }

    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    static byte[] h(String s) { return Crypto.unhex(s); }

    // ---- crypto ----

    static void crypto() throws Exception {
        // RFC 7748 5.2
        check(Crypto.hex(Crypto.x25519(h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")))
                .equals("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), "x25519 vector");
        // RFC 7748 6.1
        byte[] a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        check(Crypto.hex(Crypto.x25519(a, Crypto.BASE)).equals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), "x25519 public");
        check(Crypto.hex(Crypto.x25519(a, Crypto.x25519(b, Crypto.BASE))).equals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"), "x25519 shared");
        // against the JDK's X25519
        for (int i = 0; i < 20; i++) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("X25519");
            KeyPair p = g.generateKeyPair(), q = g.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(p.getPrivate());
            ka.doPhase(q.getPublic(), true);
            byte[] want = ka.generateSecret();
            byte[] priv = Arrays.copyOfRange(p.getPrivate().getEncoded(), 16, 48); // PKCS#8 for X25519 is a 16-byte header
            java.math.BigInteger u = ((XECPublicKey) q.getPublic()).getU();
            byte[] be = u.toByteArray(), le = new byte[32];
            for (int j = 0; j < 32 && j < be.length; j++) le[j] = be[be.length - 1 - j];
            check(Arrays.equals(Crypto.x25519(priv, le), want), "x25519 against the JDK");
        }
        // RFC 8439 2.8.2
        byte[] key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = h("070000004041424344454647"), aad = h("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .getBytes(StandardCharsets.US_ASCII);
        byte[] sealed = Crypto.seal(key, nonce, aad, pt);
        check(Crypto.hex(Arrays.copyOfRange(sealed, pt.length, sealed.length)).equals("1ae10b594f09e26a7e902ecbd0600691"), "poly1305 tag");
        check(Crypto.hex(sealed).startsWith("d31a8d34648e60db7b86afbc53ef7ec2"), "chacha20 ciphertext");
        check(Arrays.equals(Crypto.open(key, nonce, aad, sealed), pt), "aead open");
        sealed[3] ^= 1;
        check(Crypto.open(key, nonce, aad, sealed) == null, "aead tamper");
        // against the JDK's ChaCha20-Poly1305
        for (int n : new int[] {0, 1, 15, 16, 17, 63, 64, 65, 643, 2000}) {
            byte[] k = Crypto.random(32), iv = Crypto.random(12), ad = Crypto.random(n % 40), p = Crypto.random(n);
            Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "ChaCha20"), new IvParameterSpec(iv));
            c.updateAAD(ad);
            check(Arrays.equals(c.doFinal(p), Crypto.seal(k, iv, ad, p)), "aead against the JDK, " + n + " bytes");
        }
        System.out.println("crypto ok");
    }

    // ---- the handshake ----

    static void noise() throws Exception {
        for (boolean same : new boolean[] {true, false}) {
            try (ServerSocket ss = new ServerSocket(0)) {
                byte[] k1 = T5Link.key(WORD), k2 = T5Link.key(same ? WORD : "other");
                java.util.concurrent.Future<Sealed> srv = pool.submit(() -> {
                    Socket s = ss.accept();
                    try {
                        return Sealed.server(s.getInputStream(), s.getOutputStream(), T5Link.PROTOCOL, k1);
                    } catch (IOException e) {
                        s.close(); // as a device does
                        throw e;
                    }
                });
                Socket c = new Socket("127.0.0.1", ss.getLocalPort());
                c.setSoTimeout(5000);
                try {
                    Sealed cli = Sealed.client(c.getInputStream(), c.getOutputStream(), T5Link.PROTOCOL, k2);
                    check(same, "a different word must not shake hands");
                    Sealed s = srv.get(2, TimeUnit.SECONDS);
                    cli.write("hello".getBytes(StandardCharsets.UTF_8));
                    byte[] got = new byte[5];
                    s.readFully(got);
                    check(new String(got, StandardCharsets.UTF_8).equals("hello"), "sealed round trip");
                    byte[] big = Crypto.random(70000);
                    pool.execute(() -> { try { s.write(big); } catch (IOException ignored) {} });
                    byte[] back = new byte[70000];
                    cli.readFully(back);
                    check(Arrays.equals(big, back), "a message over two records");
                } catch (IOException e) {
                    check(!same, "the same word must shake hands: " + e);
                    boolean refused = false;
                    try {
                        srv.get(2, TimeUnit.SECONDS);
                    } catch (java.util.concurrent.ExecutionException x) {
                        refused = x.getCause() instanceof Sealed.KeyException;
                    }
                    check(refused, "the device sees a different key");
                }
                c.close();
            }
        }
        System.out.println("noise ok");
    }

    static void auth() {
        Ks.Auth a = new Ks.Auth(KEY);
        String t = a.token("call1", "kiosk1");
        check(a.verify(t, "call1"), "a fresh token");
        check(!a.verify(t, "call1"), "a token used twice");
        check(!a.verify(a.token("call1", "k"), "call2"), "a token for another call");
        check(!new Ks.Auth("other").verify(a.token("c", "k"), "c"), "a token from another key");
        check(Ks.digest(KEY).length() == 8, "digest");
        System.out.println("auth ok");
    }

    // ---- fakes ----

    /** mDNS in memory, shared by everyone in a test; each user advertises from its own address. */
    static final class FakeMdns implements Mdns {
        static final List<Object[]> ads = new CopyOnWriteArrayList<>(); // {instance, type, address, port, txt}
        final String address;
        FakeMdns(String address) { this.address = address; }

        @Override public List<Service> browse(String type, long lookMs) {
            List<Service> out = new ArrayList<>();
            for (Object[] a : ads) {
                @SuppressWarnings("unchecked") Map<String, String> txt = (Map<String, String>) a[4];
                if (a[1].equals(type)) out.add(new Service((String) a[0], (String) a[2], (Integer) a[3], txt));
            }
            return out;
        }

        @Override public Closeable advertise(String instance, String type, int port, Map<String, String> txt) {
            Object[] a = {instance, type, address, port, new LinkedHashMap<>(txt)};
            ads.add(a);
            return () -> ads.remove(a);
        }
    }

    /** A Kiosk Satellite kiosk: identity, calls, and the audio socket either way. */
    static final class FakeKiosk {
        final Ks.Auth auth = new Ks.Auth(KEY);
        final String id = "kiosk0000000001", name = "Office Tablet";
        final Http.Server srv;
        final BlockingQueue<Object> got = new LinkedBlockingQueue<>(); // call bodies, signals and sockets
        volatile String answer = "ringing";

        FakeKiosk() throws IOException {
            srv = new Http.Server("127.0.0.1", 0, this::serve, pool);
        }

        int port() { return srv.port(); }

        void serve(Http.Request r) throws IOException {
            if (r.path.equals("/api/intercom/identity")) {
                Map<String, Object> ep = new LinkedHashMap<>();
                ep.put("port", port());
                ep.put("tls", false);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", id); m.put("name", name); m.put("enabled", true); m.put("key", auth.keyDigest()); m.put("dnd", false);
                m.put("endpoint", ep);
                r.json(200, m);
            } else if (r.path.equals("/api/intercom/call")) {
                Map<String, Object> body = Json.object(r.body);
                check(auth.verify(r.header("authorization").substring(7), Json.str(body, "call")), "the bridge's call token");
                got.add(body);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("status", answer);
                r.json(200, m);
            } else if (r.path.startsWith("/api/intercom/call/")) {
                got.add(new Bridge.Signal(Json.str(Json.object(r.body), "action")));
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ok", true);
                r.json(200, m);
            } else if (r.path.startsWith("/api/intercom/audio/")) {
                WebSocket ws = WebSocket.upgrade(r);
                got.add(ws);
            } else {
                r.json(404, new LinkedHashMap<String, Object>());
            }
        }

        void advertise(FakeMdns m) throws IOException {
            Map<String, String> txt = new LinkedHashMap<>();
            txt.put("id", id); txt.put("name", name); txt.put("version", "test"); txt.put("port", Integer.toString(port()));
            m.advertise("ks-" + id, Bridge.KIOSK_SERVICE, port(), txt);
        }

        Object next(Class<?> kind) throws InterruptedException {
            while (true) {
                Object o = got.poll(5, TimeUnit.SECONDS);
                check(o != null, "the kiosk heard nothing, waiting for " + kind.getSimpleName());
                if (kind.isInstance(o)) return o;
            }
        }
    }

    /** A TECHO5 device that answers calls and takes announcements. */
    static final class FakeEcho {
        final String name = "Gen2 Echo";
        final Http.Server srv;
        final BlockingQueue<Object> inbox = new LinkedBlockingQueue<>();
        final BlockingQueue<Object> got = new LinkedBlockingQueue<>(); // links, callers and announcements
        final T5Announce ann = new T5Announce(WORD);

        FakeEcho() throws IOException {
            srv = new Http.Server("127.0.0.1", 0, this::serve, pool);
        }

        void serve(Http.Request r) throws IOException {
            if (r.path.equals(T5Announce.PATH)) {
                T5Announce.Message m = ann.receive(r);
                if (m != null) got.add(m);
                return;
            }
            r.taken = true;
            T5Link.Accepted a = T5Link.accept(r, T5Link.key(WORD), inbox);
            got.add(a.caller);
            a.link.say(T5Link.RINGING);
            a.link.say(T5Link.ANSWER);
            got.add(a.link);
        }

        void advertise(FakeMdns m) throws IOException {
            Map<String, String> txt = new LinkedHashMap<>();
            txt.put("name", name);
            m.advertise("gen2-echo", Bridge.ECHO_SERVICE, srv.port(), txt);
        }
    }

    static Bridge.Config config() {
        Bridge.Config c = new Bridge.Config();
        c.intercomKey = KEY;
        c.houseWord = WORD;
        c.advertise = "127.0.0.1";
        c.listen = "127.0.0.1";
        c.browseForMs = 10;
        c.portLow = 42000 + (int) (Math.random() * 1000) * 10;
        c.portHigh = c.portLow + 9;
        c.version = "test";
        return c;
    }

    static final Bridge.Log QUIET = new Bridge.Log() {
        @Override public void info(String m) { System.out.println("  " + m); }
        @Override public void warn(String m) { System.out.println("  ! " + m); }
    };

    static byte[] tone(int n, int amp) {
        byte[] b = new byte[n];
        for (int i = 0; i + 1 < n; i += 2) {
            short v = (short) (amp * Math.sin(i / 10.0));
            b[i] = (byte) v;
            b[i + 1] = (byte) (v >> 8);
        }
        return b;
    }

    // ---- calls ----

    static void kioskCallsEcho() throws Exception {
        FakeMdns.ads.clear();
        FakeMdns net = new FakeMdns("127.0.0.1");
        FakeKiosk kiosk = new FakeKiosk();
        FakeEcho echo = new FakeEcho();
        kiosk.advertise(net);
        echo.advertise(net);
        Bridge b = new Bridge(config(), net, pool, QUIET);
        b.scan();
        check(b.kioskCount() == 1 && b.echoCount() == 1, "the bridge found both");
        // the kiosk finds the Echo's stand-in and calls it
        Mdns.Service standin = null;
        for (Mdns.Service s : net.browse(Bridge.KIOSK_SERVICE, 0)) if (s.txt("id").equals(Bridge.standinId("Gen2 Echo"))) standin = s;
        check(standin != null && standin.txt("name").equals("Gen2 Echo"), "the Echo's stand-in kiosk is advertised");
        String call = "call-k2e";
        Ks.Client kc = new Ks.Client(kiosk.auth);
        Ks.Peer me = new Ks.Peer();
        me.id = kiosk.id; me.name = kiosk.name; me.address = "127.0.0.1"; me.port = kiosk.port();
        check(kc.call("127.0.0.1", standin.port, call, "call", me).equals("ringing"), "the stand-in rings");
        check(echo.got.poll(5, TimeUnit.SECONDS).equals("Office Tablet"), "the Echo hears who calls");
        T5Link link = (T5Link) echo.got.poll(5, TimeUnit.SECONDS);
        check(((Bridge.Signal) kiosk.next(Bridge.Signal.class)).action.equals("answer"), "the kiosk is told the Echo answered");
        WebSocket ws = kc.dialAudio("127.0.0.1", standin.port, call, kiosk.id);
        check(ws.read().text().contains("talk"), "the bridge says it talks");
        ws.send(WebSocket.BINARY, tone(Ks.FRAME_BYTES, 8000));
        boolean heard = false;
        for (int i = 0; i < 50 && !heard; i++) {
            byte[] f = link.audio.poll(1, TimeUnit.SECONDS);
            heard = f != null && Relay.rms(f, f.length) > 1000;
        }
        check(heard, "the Echo hears the kiosk");
        for (int i = 0; i < 4; i++) link.sendAudio(tone(T5Link.FRAME_BYTES, 8000));
        WebSocket.Message m = ws.read();
        check(m.kind == WebSocket.BINARY && m.data.length == Ks.FRAME_BYTES && Relay.rms(m.data, m.data.length) > 1000, "the kiosk hears the Echo");
        ws.sendText("{\"type\":\"end\"}");
        Object ev;
        do ev = echo.inbox.poll(5, TimeUnit.SECONDS); while (ev != null && ev != T5Link.GONE);
        check(ev == T5Link.GONE, "the Echo is hung up on");
        b.close();
        kiosk.srv.close();
        echo.srv.close();
        System.out.println("kiosk calls Echo ok");
    }

    static void echoCallsKiosk() throws Exception {
        FakeMdns.ads.clear();
        FakeMdns net = new FakeMdns("127.0.0.1");
        FakeKiosk kiosk = new FakeKiosk();
        FakeEcho echo = new FakeEcho();
        kiosk.advertise(net);
        echo.advertise(net);
        Bridge b = new Bridge(config(), net, pool, QUIET);
        b.scan();
        Mdns.Service standin = null;
        for (Mdns.Service s : net.browse(Bridge.ECHO_SERVICE, 0)) if (s.txt("name").equals("Office Tablet")) standin = s;
        check(standin != null, "the kiosk's stand-in TECHO5 device is advertised");
        BlockingQueue<Object> inbox = new LinkedBlockingQueue<>();
        T5Link link = T5Link.dial("127.0.0.1", standin.port, T5Link.key(WORD), "Gen2 Echo", inbox);
        @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) kiosk.next(Map.class);
        String call = Json.str(body, "call");
        check(Json.str(Json.obj(body, "from"), "id").equals(Bridge.standinId("Gen2 Echo")), "the call comes from the Echo's stand-in");
        check(Json.str(Json.obj(body, "from"), "name").equals("Gen2 Echo"), "with the Echo's name");
        check(inbox.poll(5, TimeUnit.SECONDS).equals(T5Link.RINGING), "the Echo hears ringing");
        // the kiosk answers
        Ks.Client kc = new Ks.Client(kiosk.auth);
        int echoStandinPort = (int) Json.num(Json.obj(body, "from"), "port");
        kc.signal("127.0.0.1", echoStandinPort, call, kiosk.id, "answer");
        check(inbox.poll(5, TimeUnit.SECONDS).equals(T5Link.ANSWER), "the Echo hears the answer");
        WebSocket ws = (WebSocket) kiosk.next(WebSocket.class);
        check(ws.read().text().contains("talk"), "the bridge says it talks");
        for (int i = 0; i < 4; i++) link.sendAudio(tone(T5Link.FRAME_BYTES, 8000));
        WebSocket.Message m = ws.read();
        check(m.kind == WebSocket.BINARY && Relay.rms(m.data, m.data.length) > 1000, "the kiosk hears the Echo");
        link.close();
        check(((Bridge.Signal) kiosk.next(Bridge.Signal.class)).action.equals("hangup"), "the kiosk is told the Echo hung up");
        b.close();
        kiosk.srv.close();
        echo.srv.close();
        System.out.println("Echo calls kiosk ok");
    }

    static void echoAnnouncesToKiosk() throws Exception {
        FakeMdns.ads.clear();
        FakeMdns net = new FakeMdns("127.0.0.1");
        FakeKiosk kiosk = new FakeKiosk();
        kiosk.answer = "listening";
        FakeEcho echo = new FakeEcho();
        kiosk.advertise(net);
        echo.advertise(net);
        Bridge b = new Bridge(config(), net, pool, QUIET);
        b.scan();
        Mdns.Service standin = null;
        for (Mdns.Service s : net.browse(Bridge.ECHO_SERVICE, 0)) if (s.txt("name").equals("Office Tablet")) standin = s;
        T5Announce.Message m = new T5Announce.Message();
        m.from = "Gen2 Echo";
        m.voice = tone(32000, 8000); // one second
        new T5Announce(WORD).send("127.0.0.1", standin.port, m);
        @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) kiosk.next(Map.class);
        check(Json.str(body, "kind").equals("broadcast"), "a broadcast reaches the kiosk");
        WebSocket ws = (WebSocket) kiosk.next(WebSocket.class);
        int bytes = 0;
        while (true) {
            WebSocket.Message f = ws.read();
            if (f.kind == WebSocket.TEXT && f.text().contains("end")) break;
            if (f.kind == WebSocket.BINARY) bytes += f.data.length;
        }
        check(bytes >= 32000, "the whole announcement is played: " + bytes);
        boolean refused = false;
        try {
            new T5Announce("wrong word").send("127.0.0.1", standin.port, m);
        } catch (IOException e) {
            refused = true;
        }
        check(refused, "an announcement with another house word is refused");
        b.close();
        kiosk.srv.close();
        echo.srv.close();
        System.out.println("Echo announces ok");
    }

    // ---- one bridge ----

    static void oneBridgeAtATime() throws Exception {
        FakeMdns.ads.clear();
        Bridge.Config c1 = config(), c2 = config();
        int p1 = 43000 + (int) (Math.random() * 1000), p2 = p1 + 1;
        Runner.Listener quiet = (level, text) -> {};
        Runner a = new Runner(c1, new FakeMdns("127.0.0.1"), pool, QUIET, quiet, "aaaaaaaaaaaaaaaa", p1, 50);
        Runner b = new Runner(c2, new FakeMdns("127.0.0.1"), pool, QUIET, quiet, "bbbbbbbbbbbbbbbb", p2, 50);
        Thread ta = new Thread(a::run), tb;
        ta.start();
        for (int i = 0; i < 100 && !a.active(); i++) Thread.sleep(20);
        check(a.active(), "the first bridge runs");
        tb = new Thread(b::run);
        tb.start();
        Thread.sleep(400);
        check(a.active() && !b.active(), "the second stands by");
        a.stop();
        ta.interrupt();
        for (int i = 0; i < 100 && !b.active(); i++) Thread.sleep(20);
        check(b.active(), "the second takes over when the first stops");
        b.stop();
        tb.interrupt();
        System.out.println("one bridge at a time ok");
    }
}
