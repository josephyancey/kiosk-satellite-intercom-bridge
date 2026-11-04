package dev.yancey.intercombridge;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
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
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Runs on a desktop JVM: java -ea dev.yancey.intercombridge.IntercomBridgeTest */
public final class IntercomBridgeTest {
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
        twoBridgesDoNotMirror();
        oldBridgeStandins();
        oneBridgeAtATime();
        failedLookStandsBy();
        hostileInput();
        forgedBridge();
        groupMdnsRecords();
        groupMdnsHostile();
        groupMdnsLooks();
        groupMdnsFallsBack();
        groupMdnsAnnounces();
        System.out.println("IntercomBridgeTest: all passed");
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
            srv = new Http.Server("127.0.0.1", 0, this::serve, pool, Http.BODY_MOST);
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

    /** A TECHO5 device that answers calls and takes announcements, on an address of its own as a real one is. */
    static final class FakeEcho {
        static final String ADDRESS = "127.0.0.2";
        final String name = "Gen2 Echo";
        final Http.Server srv;
        final BlockingQueue<Object> inbox = new LinkedBlockingQueue<>();
        final BlockingQueue<Object> got = new LinkedBlockingQueue<>(); // links, callers and announcements
        final T5Announce ann = new T5Announce(WORD);

        FakeEcho() throws IOException {
            srv = new Http.Server(ADDRESS, 0, this::serve, pool, Http.BODY_MOST);
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

        void advertise() throws IOException {
            Map<String, String> txt = new LinkedHashMap<>();
            txt.put("name", name);
            new FakeMdns(ADDRESS).advertise("gen2-echo", Bridge.ECHO_SERVICE, srv.port(), txt);
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
        echo.advertise();
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
        echo.advertise();
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
        echo.advertise();
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

    // ---- stand-ins ----

    /** How many services of type are advertised under name. */
    static int named(String type, String name) {
        int n = 0;
        for (Object[] a : FakeMdns.ads) {
            @SuppressWarnings("unchecked") Map<String, String> txt = (Map<String, String>) a[4];
            if (a[1].equals(type) && name.equals(txt.get("name"))) n++;
        }
        return n;
    }

    /**
     * Two bridges running at once, one on the kiosk and one on another device, each see the other's
     * stand-ins. Before 1.0.2 each took those for real devices and stood in for them in turn, so every
     * kiosk showed up twice in the kiosks' list and calls by name failed as ambiguous.
     */
    static void twoBridgesDoNotMirror() throws Exception {
        FakeMdns.ads.clear();
        FakeKiosk kiosk = new FakeKiosk();
        FakeEcho echo = new FakeEcho();
        kiosk.advertise(new FakeMdns("127.0.0.1"));
        echo.advertise();
        Bridge.Config ca = config(), cb = config();
        cb.advertise = cb.listen = "127.0.0.3";
        cb.portLow = ca.portHigh + 1;
        cb.portHigh = cb.portLow + 9;
        Bridge a = new Bridge(ca, new FakeMdns(ca.advertise), pool, QUIET);
        Bridge b = new Bridge(cb, new FakeMdns(cb.advertise), pool, QUIET);
        for (int i = 0; i < 3; i++) {
            a.scan();
            b.scan();
        }
        check(a.kioskCount() == 1 && a.echoCount() == 1, "the first bridge stands in for the real devices only: "
                + a.kioskCount() + " kiosks, " + a.echoCount() + " Echos");
        check(b.kioskCount() == 1 && b.echoCount() == 1, "so does the second: " + b.kioskCount() + " kiosks, " + b.echoCount() + " Echos");
        check(named(Bridge.KIOSK_SERVICE, "Office Tablet") == 1, "the kiosk is listed once among the kiosks");
        check(named(Bridge.ECHO_SERVICE, "Gen2 Echo") == 1, "the Echo is listed once among the Echos");
        check(named(Bridge.KIOSK_SERVICE, "Gen2 Echo") == 2 && named(Bridge.ECHO_SERVICE, "Office Tablet") == 2,
                "each bridge stands in for each real device");
        Map<String, Object> st = a.status();
        check(((List<?>) st.get("kiosks")).size() == 1 && ((List<?>) st.get("echos")).size() == 1, "the status page agrees");
        a.close();
        b.close();
        kiosk.srv.close();
        echo.srv.close();
        System.out.println("two bridges do not mirror ok");
    }

    /** Stand-ins left by a bridge before 1.0.2 carry no mark, and are still known for what they are. */
    static void oldBridgeStandins() throws Exception {
        FakeMdns.ads.clear();
        FakeKiosk kiosk = new FakeKiosk();
        FakeEcho echo = new FakeEcho();
        kiosk.advertise(new FakeMdns("127.0.0.1"));
        echo.advertise();
        FakeMdns old = new FakeMdns("127.0.0.3");
        // Its stand-in kiosk for the Echo, named with a suffix, and its stand-in Echo for the kiosk on a
        // port outside this bridge's range.
        Map<String, String> k = new LinkedHashMap<>();
        k.put("id", Bridge.standinId("Gen2 Echo"));
        k.put("name", "Gen2 Echo (Echo)");
        k.put("version", "1.0.1");
        k.put("port", "41006");
        old.advertise("ks-" + k.get("id"), Bridge.KIOSK_SERVICE, 41006, k);
        Map<String, String> e = new LinkedHashMap<>();
        e.put("name", "Office Tablet");
        old.advertise("office-tablet", Bridge.ECHO_SERVICE, 1234, e);
        Bridge.Config c = config();
        c.nameSuffix = " (Echo)";
        // Each rule on its own: a marked Echo on an address no kiosk is on and off the stand-in ports, an
        // unmarked one known only by the stand-in ports, and a marked kiosk whose id says nothing.
        Map<String, String> marked = new LinkedHashMap<>();
        marked.put("name", "Marked Echo");
        marked.put(Bridge.STANDIN_TXT, "1");
        new FakeMdns("127.0.0.4").advertise("marked-echo", Bridge.ECHO_SERVICE, 1234, marked);
        Map<String, String> ranged = new LinkedHashMap<>();
        ranged.put("name", "Ranged Echo");
        new FakeMdns("127.0.0.5").advertise("ranged-echo", Bridge.ECHO_SERVICE, c.portLow + 5, ranged);
        Map<String, String> mk = new LinkedHashMap<>();
        mk.put("id", "feedfacefeedface");
        mk.put("name", "Marked Kiosk");
        mk.put("port", "1234");
        mk.put(Bridge.STANDIN_TXT, "1");
        new FakeMdns("127.0.0.6").advertise("ks-feedfacefeedface", Bridge.KIOSK_SERVICE, 1234, mk);
        Bridge b = new Bridge(c, new FakeMdns("127.0.0.1"), pool, QUIET);
        b.scan();
        check(b.kioskCount() == 1 && b.echoCount() == 1, "an older bridge's stand-ins are not stood in for: "
                + b.kioskCount() + " kiosks, " + b.echoCount() + " Echos");
        check(named(Bridge.KIOSK_SERVICE, "Office Tablet") == 1, "the kiosk is still listed once");
        b.close();
        kiosk.srv.close();
        echo.srv.close();
        System.out.println("older bridges' stand-ins ok");
    }

    // ---- one bridge ----

    /**
     * A look for other bridges that fails, or finds one it cannot resolve, says nothing about them, so a
     * standby stays standing by; only a long run of such looks lets it take over. Rounds are run one by
     * one here, so the count is exact.
     */
    static void failedLookStandsBy() throws Exception {
        String[] mode = {"fails"}; // fails, unresolved or clear
        FakeMdns net = new FakeMdns("127.0.0.1");
        Mdns flaky = new Mdns() {
            @Override public List<Service> browse(String type, long lookMs) throws IOException {
                if (type.equals(Runner.BRIDGE_SERVICE)) {
                    if (mode[0].equals("fails")) throw new IOException("look failed");
                    return new ArrayList<>(); // as if the running bridge's record did not resolve
                }
                return net.browse(type, lookMs);
            }
            @Override public boolean lastLookComplete(String type) {
                return !type.equals(Runner.BRIDGE_SERVICE) || mode[0].equals("clear");
            }
            @Override public Closeable advertise(String instance, String type, int port, Map<String, String> txt) {
                return net.advertise(instance, type, port, txt);
            }
        };
        Runner.Listener quiet = (level, text) -> {};
        for (String m : new String[] {"fails", "unresolved"}) {
            FakeMdns.ads.clear();
            mode[0] = m;
            Runner r = new Runner(config(), flaky, pool, QUIET, quiet, "dddddddddddddddd", 0, 50);
            for (int i = 0; i < 9; i++) r.round();
            check(!r.active(), "nine rounds whose look " + m + " do not start a bridge");
            r.round();
            check(r.active(), "the tenth does, for a bridge gone without a goodbye");
            r.stop();
        }
        FakeMdns.ads.clear();
        mode[0] = "clear";
        Runner r = new Runner(config(), flaky, pool, QUIET, quiet, "dddddddddddddddd", 0, 50);
        r.round();
        check(!r.active(), "one clear round is not enough");
        mode[0] = "unresolved";
        r.round();
        mode[0] = "clear";
        r.round();
        check(!r.active(), "a round in doubt starts the count of clear ones over");
        r.round();
        check(r.active(), "two clear rounds in a row start the bridge");
        r.stop();
        System.out.println("failed look stands by ok");
    }

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

    /** A host that only claims to be a running bridge, or one with another key, does not stop this one. */
    static void forgedBridge() throws Exception {
        FakeMdns.ads.clear();
        Http.Server fake = new Http.Server("127.0.0.1", 0, r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", "0000000000000000");
            m.put("active", true);
            m.put("since", 0);
            m.put("proof", "00");
            r.json(200, m);
        }, pool);
        Map<String, String> txt = new LinkedHashMap<>();
        txt.put("id", "0000000000000000");
        new FakeMdns("127.0.0.1").advertise("intercom-bridge-0000000000000000", Runner.BRIDGE_SERVICE, fake.port(), txt);
        Bridge.Config other = config();
        other.intercomKey = "another fleet";
        int p = 44000 + (int) (Math.random() * 1000);
        Runner.Listener quiet = (level, text) -> {};
        Runner stranger = new Runner(other, new FakeMdns("127.0.0.1"), pool, QUIET, quiet, "1111111111111111", p, 50);
        Thread ts = new Thread(stranger::run);
        ts.start();
        for (int i = 0; i < 100 && !stranger.active(); i++) Thread.sleep(20);
        check(stranger.active(), "a bridge of another fleet runs");
        Runner b = new Runner(config(), new FakeMdns("127.0.0.1"), pool, QUIET, quiet, "bbbbbbbbbbbbbbbb", p + 1, 50);
        Thread tb = new Thread(b::run);
        tb.start();
        for (int i = 0; i < 100 && !b.active(); i++) Thread.sleep(20);
        Thread.sleep(300);
        check(b.active(), "a forged status page and another fleet's bridge do not make this one stand by");

        // A standby's real answer, relayed with "active" turned on, must not pass for a running bridge.
        Runner c = new Runner(config(), new FakeMdns("127.0.0.1"), pool, QUIET, quiet, "0ccccccccccccccc", p + 2, 50);
        Thread tc = new Thread(c::run);
        tc.start();
        Thread.sleep(300);
        check(!c.active(), "a third bridge stands by");
        Http.Server relay = new Http.Server("127.0.0.1", 0, r -> {
            Http.Response real = Http.request("GET", "127.0.0.1", p + 2, "/status?" + r.query, null, null, 2000);
            Map<String, Object> m = Json.object(real.body);
            m.put("active", true);
            r.json(200, m);
        }, pool);
        Map<String, String> ctxt = new LinkedHashMap<>();
        ctxt.put("id", "0ccccccccccccccc");
        new FakeMdns("127.0.0.1").advertise("intercom-bridge-0ccccccccccccccc", Runner.BRIDGE_SERVICE, relay.port(), ctxt);
        Thread.sleep(400);
        check(b.active(), "a relayed standby's answer does not make the running bridge stand down");
        c.stop();
        tc.interrupt();
        relay.close();
        b.stop();
        tb.interrupt();
        stranger.stop();
        ts.interrupt();
        fake.close();
        System.out.println("forged bridge ok");
    }

    /** What a host on the network can send without a key ends that request and nothing else. */
    static void hostileInput() throws Exception {
        Http.Server srv = new Http.Server("127.0.0.1", 0, r -> r.text(200, "ok"), pool, Http.SMALL_BODY);
        for (String size : new String[] {"-1", "7fffffff", "-80000000", "zz"}) {
            String reply = raw(srv.port(), "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + size + "\r\n");
            check(!reply.startsWith("HTTP/1.1 200"), "a chunk of size " + size + " is refused");
        }
        check(raw(srv.port(), "POST / HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n").isEmpty(), "a body over the port's limit is refused");
        check(raw(srv.port(), "GET / HTTP/1.1\r\nConnection: close\r\n\r\n").startsWith("HTTP/1.1 200"), "the server still answers");

        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 200000; i++) deep.append('[');
        check(Json.object(deep.toString().getBytes(StandardCharsets.UTF_8)).isEmpty(), "deep JSON is refused, not overflowed");
        try {
            Json.parse(deep.toString());
            check(false, "deep JSON parses");
        } catch (IOException expected) {
        }
        check(Json.object("{\"a\":[[{\"b\":1}]]}".getBytes(StandardCharsets.UTF_8)).containsKey("a"), "ordinary JSON still parses");

        Ks.Auth auth = new Ks.Auth(KEY);
        Http.Server standin = new Http.Server("127.0.0.1", 0, Ks.standin("id", "name", "v", new int[1], auth, null), pool, Http.SMALL_BODY);
        String reply = raw(standin.port(), "POST /api/intercom/call HTTP/1.1\r\nContent-Length: " + 20000 + "\r\nConnection: close\r\n\r\n"
                + deep.substring(0, 20000));
        check(reply.startsWith("HTTP/1.1 403"), "a call with no token is refused before its body is read");

        List<Socket> held = new ArrayList<>();
        for (int i = 0; i < 20; i++) held.add(new Socket("127.0.0.1", srv.port()));
        Thread.sleep(200);
        check(raw(srv.port(), "GET / HTTP/1.1\r\nConnection: close\r\n\r\n").isEmpty(), "connections past the port's limit are closed");
        for (Socket s : held) s.close();
        Thread.sleep(200);
        check(raw(srv.port(), "GET / HTTP/1.1\r\nConnection: close\r\n\r\n").startsWith("HTTP/1.1 200"), "and taken again once others close");
        srv.close();
        standin.close();

        // A WebSocket frame whose 64-bit length has the top bit set.
        try (ServerSocket ss = new ServerSocket(0)) {
            pool.execute(() -> {
                try (Socket s = ss.accept()) {
                    java.io.InputStream in = new java.io.BufferedInputStream(s.getInputStream());
                    String key = "";
                    for (String line; !(line = Http.readLine(in)).isEmpty(); ) {
                        if (line.toLowerCase(java.util.Locale.ROOT).startsWith("sec-websocket-key:")) key = line.substring(18).trim();
                    }
                    String accept = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-1")
                            .digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.ISO_8859_1)));
                    s.getOutputStream().write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                            + "Sec-WebSocket-Accept: " + accept + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().write(new byte[] {(byte) 0x82, 127, (byte) 0x80, 0, 0, 0, 0, 0, 0, 1});
                    s.getOutputStream().flush();
                    Thread.sleep(1000);
                } catch (Exception ignored) {
                }
            });
            WebSocket ws = WebSocket.dial("127.0.0.1", ss.getLocalPort(), "/", 2000);
            try {
                ws.read();
                check(false, "a negative WebSocket length is read");
            } catch (IOException expected) {
            }
            ws.close();
        }
        System.out.println("hostile input ok");
    }

    // ---- the bridge's own mDNS listener ----

    static byte[] dnsName(String... labels) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (String l : labels) {
            byte[] b = l.getBytes(StandardCharsets.UTF_8);
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        o.write(0);
        return o.toByteArray();
    }

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    static byte[] u16(int v) { return new byte[] {(byte) (v >> 8), (byte) v}; }

    static byte[] rr(byte[] name, int type, long ttl, byte[] data) {
        return cat(name, u16(type), u16(0x8001), u16((int) (ttl >> 16)), u16((int) ttl), u16(data.length), data);
    }

    /** A response with the given records as answers, under flags (0x8400 for an authoritative answer). */
    static byte[] dnsResponse(int flags, byte[]... records) {
        return cat(u16(0), u16(flags), u16(0), u16(records.length), u16(0), u16(0), cat(records));
    }

    static byte[] srvData(int port, byte[] target) { return cat(u16(0), u16(0), u16(port), target); }

    static byte[] txtData(String... entries) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (String e : entries) {
            byte[] b = e.getBytes(StandardCharsets.UTF_8);
            o.write(b.length);
            o.write(b, 0, b.length);
        }
        return o.toByteArray();
    }

    static byte[] aData(int a, int b, int c, int d) { return new byte[] {(byte) a, (byte) b, (byte) c, (byte) d}; }

    static void groupMdnsRecords() {
        String domain = "_t._tcp.local";
        GroupMdns.Cache c = new GroupMdns.Cache();
        byte[] type = dnsName("_t", "_tcp", "local"), inst = dnsName("Office Tablet", "_t", "_tcp", "local");
        byte[] host = dnsName("office", "local");
        byte[] full = dnsResponse(0x8400,
                rr(type, 12, 120, inst),
                rr(inst, 33, 120, srvData(2324, host)),
                rr(inst, 16, 120, txtData("id=1", "name=Office Tablet", "ID=2", "flag", "")),
                rr(host, 1, 120, aData(10, 0, 0, 5)));
        c.handle(full, full.length, "10.0.0.99", 1000);
        GroupMdns.Cache.Look l = c.look(domain, 2000);
        check(l.found == 1 && l.complete == 1 && l.services.size() == 1, "one service, complete");
        Mdns.Service s = l.services.get(0);
        check(s.instance.equals("Office Tablet") && s.address.equals("10.0.0.5") && s.port == 2324, "instance, address and port");
        check(s.txt("id").equals("1") && s.txt("name").equals("Office Tablet") && s.txt.containsKey("flag") && s.txt("flag").isEmpty(),
                "TXT: first of a key counts, keys ignore case, a bare key is empty");
        check(c.look("_T._TCP.local", 2000).found == 1, "domains match without regard to case");
        check(c.missing(domain, 2000).isEmpty(), "nothing missing");

        // Expired after its time to live; gone at once with a goodbye.
        check(c.look(domain, 1000 + 121000).found == 0, "expires with its TTL");
        c.handle(full, full.length, "10.0.0.99", 200000);
        byte[] bye = dnsResponse(0x8400, rr(type, 12, 0, inst));
        c.handle(bye, bye.length, "10.0.0.99", 200001);
        check(c.look(domain, 200002).found == 0, "a goodbye ends it");

        // Only a PTR: the look asks for the rest, then for the host's address.
        GroupMdns.Cache d = new GroupMdns.Cache();
        byte[] dotted = dnsName("Mr. Echo", "_t", "_tcp", "local");
        byte[] ptr = dnsResponse(0x8400, rr(type, 12, 120, dotted));
        d.handle(ptr, ptr.length, "10.0.0.7", 0);
        List<String[]> q = d.missing(domain, 1);
        check(q.size() == 2 && q.get(0)[1].equals("33") && q.get(1)[1].equals("16"), "asks for SRV and TXT: " + q.size());
        GroupMdns.Reader asked = new GroupMdns.Reader(GroupMdns.Cache.query(q.get(0)[0], 33), 512);
        asked.pos = 12;
        check(asked.name().equals(Arrays.asList("Mr. Echo", "_t", "_tcp", "local")), "an instance with a dot stays one label");
        GroupMdns.Cache.Look partial = d.look(domain, 1);
        check(partial.found == 1 && partial.complete == 0 && partial.services.isEmpty(), "found but not resolved");
        byte[] srv = dnsResponse(0x8400, rr(dotted, 33, 120, srvData(41000, dnsName("bridge", "local"))));
        d.handle(srv, srv.length, "10.0.0.7", 2);
        q = d.missing(domain, 3);
        check(q.size() == 2 && q.get(1)[1].equals("1") && q.get(1)[0].equals("bridge.local"), "then the address of its host");
        check(d.look(domain, 3).services.isEmpty(), "not returned without its TXT, which says whether it is a stand-in");
        byte[] txt = dnsResponse(0x8400, rr(dotted, 16, 120, txtData("standin=1")));
        d.handle(txt, txt.length, "10.0.0.7", 3);
        partial = d.look(domain, 3);
        check(partial.services.size() == 1 && partial.services.get(0).address.equals("10.0.0.7") && partial.complete == 0,
                "without an address record, the sender's address, and still incomplete");
        // A goodbye for a record replaced since leaves the new one alone.
        byte[] oldSrvBye = dnsResponse(0x8400, rr(dotted, 33, 0, srvData(40999, dnsName("bridge", "local"))));
        byte[] oldTxtBye = dnsResponse(0x8400, rr(dotted, 16, 0, txtData("standin=0")));
        d.handle(oldSrvBye, oldSrvBye.length, "10.0.0.7", 4);
        d.handle(oldTxtBye, oldTxtBye.length, "10.0.0.7", 4);
        check(d.look(domain, 5).services.size() == 1, "goodbyes for old records do not end the new ones");
        byte[] srvBye = dnsResponse(0x8400, rr(dotted, 33, 0, srvData(41000, dnsName("bridge", "local"))));
        d.handle(srvBye, srvBye.length, "10.0.0.7", 6);
        check(d.look(domain, 7).services.isEmpty(), "a goodbye for its own record does");

        // Asked for its port and never answering, it has gone, until it sends its PTR again.
        GroupMdns.Cache g = new GroupMdns.Cache();
        g.handle(ptr, ptr.length, "10.0.0.7", 0);
        check(g.missing(domain, 0).size() == 2 && g.look(domain, 1).found == 1, "found, and asked about");
        long later = GroupMdns.Cache.GONE_MS;
        GroupMdns.Cache.Look gone = g.look(domain, later);
        check(gone.found == 0 && gone.gone == 1, "gone once unanswered, and counted as a doubt");
        List<String[]> still = g.missing(domain, later);
        check(still.size() == 1 && still.get(0)[1].equals("33"), "still asked for its port alone");
        g.handle(ptr, ptr.length, "10.0.0.7", later + 1);
        check(g.look(domain, later + 2).found == 1, "back with its PTR");
        GroupMdns.Cache h = new GroupMdns.Cache();
        h.handle(ptr, ptr.length, "10.0.0.7", 0);
        h.missing(domain, 0);
        h.handle(srv, srv.length, "10.0.0.7", later + 1);
        check(h.look(domain, later + 2).found == 1, "or with its port, answered at last");

        // A compressed name, pointing back at the type's name.
        GroupMdns.Cache e = new GroupMdns.Cache();
        byte[] head = cat(u16(0), u16(0x8400), u16(0), u16(2), u16(0), u16(0));
        int typeAt = head.length;
        byte[] ptr2 = cat(head, rr(type, 12, 120, cat(new byte[] {4, 'K', 'i', 't', 'c'}, new byte[] {(byte) 0xc0, (byte) typeAt})));
        int instAt = typeAt + type.length + 10;
        byte[] packed = cat(ptr2, rr(new byte[] {(byte) 0xc0, (byte) instAt}, 33, 120, srvData(9, new byte[] {(byte) 0xc0, (byte) typeAt})));
        e.handle(packed, packed.length, "10.0.0.8", 0);
        byte[] kitcTxt = dnsResponse(0x8400, rr(dnsName("Kitc", "_t", "_tcp", "local"), 16, 120, txtData("id=k")));
        e.handle(kitcTxt, kitcTxt.length, "10.0.0.8", 0);
        GroupMdns.Cache.Look k = e.look(domain, 1);
        check(k.found == 1 && k.services.size() == 1 && k.services.get(0).instance.equals("Kitc") && k.services.get(0).port == 9,
                "compressed names read");

        // A query, or an error response, adds nothing; nor does an instance of another domain.
        GroupMdns.Cache f = new GroupMdns.Cache();
        byte[] query = dnsResponse(0x0000, rr(type, 12, 120, inst));
        byte[] error = dnsResponse(0x8403, rr(type, 12, 120, inst));
        byte[] other = dnsResponse(0x8400, rr(type, 12, 120, dnsName("X", "_u", "_tcp", "local")));
        for (byte[] p : new byte[][] {query, error, other}) f.handle(p, p.length, "10.0.0.9", 0);
        check(f.look(domain, 1).found == 0, "queries, errors and strangers' instances ignored");
    }

    static void groupMdnsHostile() {
        String domain = "_t._tcp.local";
        byte[] type = dnsName("_t", "_tcp", "local"), inst = dnsName("A", "_t", "_tcp", "local");
        byte[] full = dnsResponse(0x8400, rr(type, 12, 120, inst), rr(inst, 33, 120, srvData(1, dnsName("h", "local"))));
        // Cut short anywhere: nothing taken, nothing thrown.
        for (int n = 0; n < full.length; n++) {
            GroupMdns.Cache c = new GroupMdns.Cache();
            c.handle(full, n, "10.0.0.1", 0);
            check(c.look(domain, 1).found == 0, "a cut-off packet adds nothing (" + n + ")");
        }
        // Pointer loops, forward pointers and bad labels.
        GroupMdns.Cache c = new GroupMdns.Cache();
        byte[] head = cat(u16(0), u16(0x8400), u16(0), u16(1), u16(0), u16(0));
        for (byte[] bad : new byte[][] {
                cat(head, new byte[] {(byte) 0xc0, 12}), // points at itself
                cat(head, new byte[] {(byte) 0xc0, 40}), // points forward
                cat(head, new byte[] {(byte) 0x80, 1}), // a reserved label kind
                cat(head, new byte[] {63, 'a'})}) { // runs past the end
            c.handle(bad, bad.length, "10.0.0.1", 0);
        }
        // Noise, and a flood of instances: bounded.
        Random rnd = new Random(7);
        for (int i = 0; i < 20000; i++) {
            byte[] junk = new byte[rnd.nextInt(80)];
            rnd.nextBytes(junk);
            if (junk.length > 3) { junk[2] = (byte) 0x84; junk[3] = 0; }
            c.handle(junk, junk.length, "10.0.0.1", 0);
        }
        for (int i = 0; i < 3000; i++) {
            byte[] p = dnsResponse(0x8400, rr(type, 12, 120, dnsName("n" + i, "_t", "_tcp", "local")));
            c.handle(p, p.length, "10.0.0.1", 0);
        }
        int found = c.look(domain, 1).found;
        check(found > 0 && found <= 1024, "instances kept are bounded: " + found);
        check(c.missing(domain, 1).size() <= 66, "questions per look are bounded");
        // Each new PTR paired with a short-lived SRV, so every packet finds something expired to purge.
        GroupMdns.Cache f = new GroupMdns.Cache();
        byte[] other = dnsName("_x", "_tcp", "local");
        for (int i = 0; i < 3000; i++) {
            byte[] n = dnsName("p" + i, "_x", "_tcp", "local");
            byte[] p = dnsResponse(0x8400, rr(other, 12, 4000, n), rr(n, 33, 1, srvData(1, dnsName("h", "local"))));
            f.handle(p, p.length, "10.0.0.1", i * 2000L);
        }
        int kept = f.look("_x._tcp.local", 6000000).found + f.look("_x._tcp.local", 6000000).gone;
        check(kept <= 1024, "PTRs stay bounded while other records expire: " + kept);
        // A long chain of backward pointers is refused rather than followed.
        ByteArrayOutputStream chain = new ByteArrayOutputStream();
        byte[] h0 = cat(u16(0), u16(0x8400), u16(0), u16(1), u16(0), u16(0));
        chain.write(h0, 0, h0.length);
        chain.write(1); chain.write('a'); chain.write(0);
        for (int i = 0; i < 100; i++) {
            int at = chain.size() - (i == 0 ? 3 : 2);
            chain.write(0xc0 | at >> 8); chain.write(at);
        }
        byte[] ptrRec = rr(new byte[] {(byte) 0xc0, (byte) 12}, 12, 120, inst);
        byte[] tail = cat(chain.toByteArray(), ptrRec);
        new GroupMdns.Cache().handle(tail, tail.length, "10.0.0.1", 0); // must not throw
        GroupMdns.Reader deep = new GroupMdns.Reader(tail, tail.length);
        deep.pos = tail.length - ptrRec.length - 2;
        try {
            deep.name();
            check(false, "a 100-pointer chain is followed");
        } catch (IllegalArgumentException expected) {
        }
    }

    /** Answers questions straight to the asker, PTR alone at first, as a legacy-query responder does. */
    static MulticastSocket fakeResponder(int port) throws IOException {
        InetAddress g = InetAddress.getByName(GroupMdns.GROUP);
        MulticastSocket s = new MulticastSocket(new InetSocketAddress(g, port));
        if (GroupMdns.join(s, g, port) == 0) s.joinGroup(g);
        byte[] type = dnsName("_t", "_tcp", "local"), inst = dnsName("Fake Echo", "_t", "_tcp", "local");
        byte[] host = dnsName("fake", "local");
        DatagramSocket reply = new DatagramSocket(); // a socket bound to the group's address cannot send
        pool.execute(() -> {
            byte[] buf = new byte[1500];
            while (!s.isClosed()) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                    GroupMdns.Reader r = new GroupMdns.Reader(p.getData(), p.getLength());
                    r.pos = 2;
                    if ((r.u16() & 0x8000) != 0) continue;
                    r.pos = 12;
                    List<String> name = r.name();
                    int t = r.u16();
                    byte[] answer;
                    if (t == 12 && name.get(0).equals("_t")) answer = rr(type, 12, 120, inst);
                    else if (t == 33 && name.get(0).equals("Fake Echo")) answer = rr(inst, 33, 120, srvData(4242, host));
                    else if (t == 16 && name.get(0).equals("Fake Echo")) answer = rr(inst, 16, 120, txtData("id=x"));
                    else if (t == 1 && name.get(0).equals("fake")) answer = rr(host, 1, 120, aData(10, 9, 8, 7));
                    else continue;
                    byte[] out = dnsResponse(0x8400, answer);
                    reply.send(new DatagramPacket(out, out.length, p.getAddress(), p.getPort()));
                } catch (IOException | RuntimeException e) {
                    if (s.isClosed()) break;
                }
            }
            reply.close();
        });
        return s;
    }

    static final ThreadFactory DAEMONS = r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    };

    static void groupMdnsLooks() throws Exception {
        int port = 25353;
        Mdns refuse = new Mdns() {
            @Override public List<Service> browse(String type, long lookMs) throws IOException { throw new IOException("fell back"); }
            @Override public Closeable advertise(String i, String t, int p, Map<String, String> txt) { return () -> {}; }
        };
        MulticastSocket responder = fakeResponder(port);
        GroupMdns m = new GroupMdns(refuse, DAEMONS, "", GroupMdns.GROUP, port, GroupMdns.ANNOUNCE_MS);
        try {
            check(!m.diagnostics().containsKey("listener"), "listening to the group: " + m.diagnostics());
            List<Mdns.Service> found = m.browse("_t._tcp", 2500);
            check(found.size() == 1, "found the responder's service: " + m.diagnostics());
            Mdns.Service s = found.get(0);
            check(s.instance.equals("Fake Echo") && s.address.equals("10.9.8.7") && s.port == 4242 && s.txt("id").equals("x"),
                    "resolved through follow-up questions");
            check(m.lastLookComplete("_t._tcp"), "the look is complete");
            check(m.diagnostics().get("_t._tcp").equals("1 found, 1 resolved"), "diagnostics: " + m.diagnostics());
            check(m.browse("_none._tcp", 600).isEmpty() && m.lastLookComplete("_none._tcp"), "nothing found is a complete look");
        } finally {
            m.close();
            responder.close();
        }
        try {
            m.browse("_t._tcp", 100);
            check(false, "a closed listener looks no more");
        } catch (IOException expected) {
        }
    }

    static void groupMdnsFallsBack() throws Exception {
        FakeMdns.ads.clear();
        FakeMdns fake = new FakeMdns("10.0.0.1");
        fake.advertise("Kept", "_t._tcp", 1, new LinkedHashMap<>());
        GroupMdns m = new GroupMdns(fake, DAEMONS, "", "10.255.255.1", 25354, GroupMdns.ANNOUNCE_MS);
        try {
            check(String.valueOf(m.diagnostics().get("listener")).contains("Android's mDNS service looks instead"), "says it fell back");
            List<Mdns.Service> found = m.browse("_t._tcp", 10);
            check(found.size() == 1 && found.get(0).instance.equals("Kept"), "looks through the fallback");
        } finally {
            m.close();
            FakeMdns.ads.clear();
        }
    }

    /** This machine's address on the network the group's packets go out on, which a responder here answers from. */
    static String localAddress() throws IOException {
        for (java.net.NetworkInterface nic : java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())) {
            if (!nic.isUp() || nic.isLoopback() || !nic.supportsMulticast()) continue;
            for (InetAddress a : java.util.Collections.list(nic.getInetAddresses())) {
                if (a instanceof java.net.Inet4Address) return a.getHostAddress();
            }
        }
        throw new IOException("no network to test on");
    }

    /**
     * Answers questions for one stand-in as Android's mDNS service holds it: straight to the asker, from
     * this machine's address, with a host name and TXT order of its own.
     */
    static MulticastSocket fakeAndroid(int port, byte[] txt) throws IOException {
        InetAddress g = InetAddress.getByName(GroupMdns.GROUP);
        MulticastSocket s = new MulticastSocket(new InetSocketAddress(g, port));
        if (GroupMdns.join(s, g, port) == 0) s.joinGroup(g);
        byte[] inst = dnsName("ks-590a2c66906c3acf", "_kiosk-satellite", "_tcp", "local");
        byte[] host = dnsName("Android-Portal", "local");
        DatagramSocket reply = new DatagramSocket();
        pool.execute(() -> {
            byte[] buf = new byte[1500];
            while (!s.isClosed()) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                    GroupMdns.Reader r = new GroupMdns.Reader(p.getData(), p.getLength());
                    r.pos = 2;
                    if ((r.u16() & 0x8000) != 0) continue;
                    r.pos = 12;
                    List<String> name = r.name();
                    int t = r.u16();
                    byte[] answer;
                    if (t == 33 && name.get(0).equals("ks-590a2c66906c3acf")) answer = rr(inst, 33, 10, srvData(41006, host));
                    else if (t == 16 && name.get(0).equals("ks-590a2c66906c3acf")) answer = rr(inst, 16, 10, txt);
                    else if (t == 1 && name.get(0).equalsIgnoreCase("Android-Portal")) answer = rr(host, 1, 10, aData(10, 9, 8, 7));
                    else continue;
                    byte[] out = dnsResponse(0x8400, answer);
                    reply.send(new DatagramPacket(out, out.length, p.getAddress(), p.getPort()));
                } catch (IOException | RuntimeException e) {
                    if (s.isClosed()) break;
                }
            }
            reply.close();
        });
        return s;
    }

    /** Waits up to ms for the group's responses, feeding each to heard until done says so; the number heard. */
    static int hearResponses(MulticastSocket hear, GroupMdns.Cache heard, long ms, int port, int[] fromPort,
            List<byte[]> packets, java.util.function.BooleanSupplier done) throws IOException {
        int n = 0;
        long until = System.currentTimeMillis() + ms;
        byte[] buf = new byte[9000];
        while (System.currentTimeMillis() < until && (done == null || !done.getAsBoolean())) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                hear.receive(p);
            } catch (java.net.SocketTimeoutException quiet) {
                continue;
            }
            if ((buf[2] & 0x80) == 0) continue; // questions
            n++;
            if (fromPort != null && p.getPort() == port) fromPort[0]++;
            if (packets != null) packets.add(Arrays.copyOf(p.getData(), p.getLength()));
            heard.handle(p.getData(), p.getLength(), "10.0.0.250", System.currentTimeMillis());
        }
        return n;
    }

    static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return true;
        }
        return false;
    }

    static void groupMdnsAnnounces() throws Exception {
        int port = 25356;
        InetAddress g = InetAddress.getByName(GroupMdns.GROUP);
        MulticastSocket hear = new MulticastSocket(new InetSocketAddress(g, port));
        if (GroupMdns.join(hear, g, port) == 0) hear.joinGroup(g);
        hear.setSoTimeout(200);
        byte[] androidTxt = txtData("name=Gen2 Echo", "id=590a2c66906c3acf", "standin=1");
        MulticastSocket android = fakeAndroid(port, androidTxt);
        boolean[] unregistered = new boolean[1];
        Mdns nsd = new Mdns() {
            @Override public List<Service> browse(String type, long lookMs) { return new ArrayList<>(); }
            @Override public Closeable advertise(String i, String t, int p, Map<String, String> txt) { return () -> unregistered[0] = true; }
        };
        GroupMdns m = new GroupMdns(nsd, DAEMONS, localAddress(), GroupMdns.GROUP, port, 400);
        String domain = "_kiosk-satellite._tcp.local";
        GroupMdns.Cache heard = new GroupMdns.Cache();
        try {
            Map<String, String> txt = new LinkedHashMap<>();
            txt.put("id", "590a2c66906c3acf");
            Closeable ad = m.advertise("ks-590a2c66906c3acf", "_kiosk-satellite._tcp", 41006, txt);
            int[] fromPort = new int[1];
            List<byte[]> packets = new ArrayList<>();
            // The first a couple of seconds on, once Android's service answered; then every 1.4 s (400 ms and the wait).
            int announcements = hearResponses(hear, heard, 5500, port, fromPort, packets, null);
            check(announcements >= 3, "announced, and again on the timer: " + announcements + "; " + m.diagnostics());
            check(fromPort[0] == announcements, "from the mDNS port, as responders expect: " + fromPort[0] + " of " + announcements);
            GroupMdns.Cache.Look look = heard.look(domain, System.currentTimeMillis());
            check(look.services.size() == 1 && look.complete == 1, "PTR, SRV, TXT and A in each: " + look.found);
            Mdns.Service s = look.services.get(0);
            check(s.instance.equals("ks-590a2c66906c3acf") && s.address.equals("10.9.8.7") && s.port == 41006
                    && s.txt("name").equals("Gen2 Echo"), "the stand-in as Android's service holds it");
            for (byte[] p : packets) {
                check(contains(p, androidTxt) && contains(p, dnsName("Android-Portal", "local")),
                        "Android's TXT bytes and SRV target, exactly, so its service sees no conflict");
            }
            check(String.valueOf(m.diagnostics().get("announcing")).startsWith("every 0 s, 1 now"), "status: " + m.diagnostics());

            ad.close();
            check(unregistered[0], "Android's registration is closed too");
            hearResponses(hear, heard, 1500, port, null, null, () -> heard.look(domain, System.currentTimeMillis()).found == 0);
            check(heard.look(domain, System.currentTimeMillis()).found == 0, "a goodbye when it is closed");
            check(hearResponses(hear, heard, 1600, port, null, null, null) == 0, "silent once closed");

            // Closing the whole listener says goodbye for what is still advertised.
            m.advertise("ks-590a2c66906c3acf", "_kiosk-satellite._tcp", 41006, txt);
            hearResponses(hear, heard, 3000, port, null, null, () -> heard.look(domain, System.currentTimeMillis()).found == 1);
            check(heard.look(domain, System.currentTimeMillis()).found == 1, "announced again");
            m.close();
            hearResponses(hear, heard, 1500, port, null, null, () -> heard.look(domain, System.currentTimeMillis()).found == 0);
            check(heard.look(domain, System.currentTimeMillis()).found == 0, "goodbyes on close");
        } finally {
            m.close();
            hear.close();
            android.close();
        }

        // Never announced while Android's service has not answered, so nothing it could take for a conflict.
        GroupMdns quiet = new GroupMdns(nsd, DAEMONS, "10.255.255.254", GroupMdns.GROUP, port + 1, 300);
        MulticastSocket hear2 = new MulticastSocket(new InetSocketAddress(g, port + 1));
        if (GroupMdns.join(hear2, g, port + 1) == 0) hear2.joinGroup(g);
        hear2.setSoTimeout(200);
        try {
            quiet.advertise("ks-unanswered", "_kiosk-satellite._tcp", 1, new LinkedHashMap<>());
            check(hearResponses(hear2, new GroupMdns.Cache(), 3000, port + 1, null, null, null) == 0, "nothing announced unanswered");
            check(String.valueOf(quiet.diagnostics().get("announcing")).contains("did not answer"), "says why: " + quiet.diagnostics());
        } finally {
            quiet.close();
            hear2.close();
        }
        check(GroupMdns.ipv4("10.1.3.148") != null && GroupMdns.ipv4("10.1.3") == null && GroupMdns.ipv4("10.1.3.256") == null
                && GroupMdns.ipv4("a.b.c.d") == null && GroupMdns.ipv4("") == null, "only dotted IPv4 addresses");
        System.out.println("announces ok");
    }

    /** Sends request as is and returns whatever comes back before the server closes or goes quiet. */
    static String raw(int port, String request) throws IOException {
        try (Socket s = new Socket("127.0.0.1", port)) {
            s.setSoTimeout(2000);
            s.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            try {
                for (int n; (n = s.getInputStream().read(buf)) > 0; ) b.write(buf, 0, n);
            } catch (IOException quiet) {
            }
            return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
        }
    }
}
