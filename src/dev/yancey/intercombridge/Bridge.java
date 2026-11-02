package dev.yancey.intercombridge;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Lets Kiosk Satellite kiosks and TECHO5 Echos call each other. Every Echo gets a stand-in kiosk
 * that the kiosks list and call; every kiosk gets a stand-in TECHO5 device that the Echos list and
 * call. A call to a stand-in becomes a call to the real device, and the bridge carries the audio.
 */
final class Bridge {
    static final String KIOSK_SERVICE = "_kiosk-satellite._tcp", ECHO_SERVICE = "_techo5._tcp";
    private static final long RING_MS = T5Link.RING_MS; // an Echo rings this long; a kiosk caller is told "missed" after it
    private static final long SOCKET_WAIT_MS = 10000; // after an answer, how long the kiosk has to open the audio socket
    private static final long ANNOUNCE_LISTEN_MS = 25000; // the most a kiosk's broadcast is gathered for

    interface Log {
        void info(String message);
        void warn(String message);
    }

    static final class Config {
        String intercomKey = "", houseWord = "";
        String advertise = ""; // the address kiosks and Echos reach the bridge on
        String listen = ""; // the address stand-ins listen on; empty is all
        int portLow = 41000, portHigh = 41099;
        File stateFile;
        String nameSuffix = ""; // added to an Echo's name in the kiosks' list
        long browseForMs = 5000, forgetAfterMs = 10 * 60000, maxCallMs = 2 * 3600000L;
        long silenceHangupMs; // ends a call once neither side has been louder than quietDbfs this long; 0 never
        double quietDbfs = -55, toEchoDb, toKioskDb;
        String version = "dev";
        boolean noAdvertise; // tests: serve stand-ins without announcing them
    }

    static final class Kiosk {
        String id, name, version, address;
        int adminPort;
    }

    static final class Echo {
        String name, address;
        int port;
    }

    /** A real kiosk and the stand-in TECHO5 device the Echos call it through. */
    private final class KioskTwin {
        volatile Kiosk k;
        int port;
        Http.Server srv;
        Closeable adv;
        volatile long seen;
    }

    /** A real Echo and the stand-in kiosk the kiosks call it through. */
    private final class EchoTwin {
        volatile Echo e;
        String id, name; // the stand-in kiosk's
        int port;
        Http.Server srv;
        Closeable adv;
        volatile long seen;
    }

    /** A kiosk's word on a call: answer, decline, missed, cancel or hangup. */
    static final class Signal {
        final String action;
        Signal(String action) { this.action = action; }
    }

    /** One call through the bridge, by its Kiosk Satellite call id. */
    private static final class Session {
        String id, way, kioskName, echoName;
        T5Link link;
        String kioskHost; // the real kiosk
        int kioskAdmin, endpoint; // its admin port, for identity, and its call port
        String fromId; // the stand-in kiosk this call is signed as
        final BlockingQueue<Object> inbox = new LinkedBlockingQueue<>(); // signals, sockets, link messages
        final long started = System.currentTimeMillis();
        volatile boolean answered;
    }

    final Config cfg;
    private final Ks.Auth auth;
    private final Ks.Client ksc;
    private final byte[] t5key;
    private final T5Announce ann;
    private final Log log;
    private final Mdns mdns;
    private final ExecutorService pool;

    private final Map<String, KioskTwin> kiosks = new HashMap<>(); // by the real kiosk's id
    private final Map<String, EchoTwin> echos = new HashMap<>(); // by the Echo's name, lower case
    private final Map<String, Session> calls = new HashMap<>();
    private Map<String, Long> ports = new HashMap<>(); // "ks:<id>" and "t5:<name>" to port, kept in stateFile
    private String lastErr = "";
    private long lastAt;

    Bridge(Config cfg, Mdns mdns, ExecutorService pool, Log log) {
        this.cfg = cfg;
        this.mdns = mdns;
        this.pool = pool;
        this.log = log;
        auth = new Ks.Auth(cfg.intercomKey);
        ksc = new Ks.Client(auth);
        t5key = T5Link.key(cfg.houseWord);
        ann = new T5Announce(cfg.houseWord);
        loadState();
    }

    /** The stand-in kiosk id for an Echo: 16 hex digits that stay the same across restarts and bridges. */
    static String standinId(String echoName) {
        return Crypto.hex(Crypto.sha256("intercom-bridge:" + echoName.toLowerCase(Locale.ROOT))).substring(0, 16);
    }

    /** Looks once for kiosks and Echos, and brings the stand-ins up to date. */
    void scan() throws InterruptedException {
        Future<List<Mdns.Service>> k = pool.submit(() -> mdns.browse(KIOSK_SERVICE, cfg.browseForMs));
        Future<List<Mdns.Service>> e = pool.submit(() -> mdns.browse(ECHO_SERVICE, cfg.browseForMs));
        try {
            setKiosks(kiosksFrom(k.get()));
        } catch (java.util.concurrent.ExecutionException x) {
            fail("looking for kiosks: " + x.getCause().getMessage());
        }
        try {
            setEchos(echosFrom(e.get()));
        } catch (java.util.concurrent.ExecutionException x) {
            fail("looking for Echos: " + x.getCause().getMessage());
        }
        forget(System.currentTimeMillis() - cfg.forgetAfterMs);
    }

    static List<Kiosk> kiosksFrom(List<Mdns.Service> found) {
        List<Kiosk> out = new ArrayList<>();
        List<String> seen = new ArrayList<>();
        for (Mdns.Service s : found) {
            Kiosk k = new Kiosk();
            k.id = s.txt("id");
            // An IPv4 address is what the kiosks give each other; mDNS may hand back IPv6 first.
            k.address = isIp(s.address) ? s.address : isIp(s.txt("host")) ? s.txt("host") : s.address == null ? "" : s.address;
            if (k.id.isEmpty() || k.address.isEmpty() || seen.contains(k.id)) continue;
            seen.add(k.id);
            k.name = s.txt("name");
            k.version = s.txt("version");
            try {
                k.adminPort = Integer.parseInt(s.txt("port"));
            } catch (NumberFormatException x) {
                k.adminPort = s.port;
            }
            out.add(k);
        }
        return out;
    }

    static List<Echo> echosFrom(List<Mdns.Service> found) {
        List<Echo> out = new ArrayList<>();
        List<String> seen = new ArrayList<>();
        for (Mdns.Service s : found) {
            Echo e = new Echo();
            e.name = s.txt("name").isEmpty() ? s.instance : s.txt("name");
            e.address = s.address;
            e.port = s.port;
            String key = e.name.toLowerCase(Locale.ROOT);
            if (e.name.isEmpty() || e.address == null || e.address.isEmpty() || "0".equals(s.txt("hears")) || seen.contains(key)) continue;
            seen.add(key);
            out.add(e);
        }
        return out;
    }

    private static boolean isIp(String s) {
        return s.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    /** Takes in the kiosks one look found. Stand-ins of our own are left out. */
    void setKiosks(List<Kiosk> found) {
        long now = System.currentTimeMillis();
        for (Kiosk k : found) {
            if (isOwnStandin(k.id)) continue;
            KioskTwin t;
            synchronized (this) {
                t = kiosks.get(k.id);
            }
            if (t != null) {
                boolean renamed = !t.k.name.equals(k.name);
                t.k = k;
                t.seen = now;
                if (renamed) readvertiseKiosk(t);
                continue;
            }
            try {
                addKiosk(k, now);
            } catch (IOException e) {
                fail("stand-in for kiosk \"" + k.name + "\": " + e.getMessage());
            }
        }
    }

    /** Takes in the Echos one look found. Stand-ins of our own are left out. */
    void setEchos(List<Echo> found) {
        long now = System.currentTimeMillis();
        for (Echo e : found) {
            if (e.address.equals(cfg.advertise) && e.port >= cfg.portLow && e.port <= cfg.portHigh) continue; // one of ours
            EchoTwin t;
            synchronized (this) {
                t = echos.get(e.name.toLowerCase(Locale.ROOT));
            }
            if (t != null) {
                t.e = e;
                t.seen = now;
                continue;
            }
            try {
                addEcho(e, now);
            } catch (IOException x) {
                fail("stand-in for Echo \"" + e.name + "\": " + x.getMessage());
            }
        }
    }

    private synchronized boolean isOwnStandin(String id) {
        for (EchoTwin t : echos.values()) if (t.id.equals(id)) return true;
        return false;
    }

    private void addKiosk(Kiosk k, long now) throws IOException {
        KioskTwin t = new KioskTwin();
        t.k = k;
        t.seen = now;
        // An announcement's voice, with room to spare: T5Announce cuts a longer one to twenty seconds.
        t.srv = listen("ks:" + k.id, r -> serveEchoCall(t, r), T5Announce.MAX_BYTES + Http.SMALL_BODY);
        t.port = t.srv.port();
        if (!cfg.noAdvertise) {
            try {
                t.adv = advertiseEcho(k.name, t.port);
            } catch (IOException e) {
                t.srv.close();
                throw new IOException("advertising: " + e.getMessage());
            }
        }
        synchronized (this) {
            kiosks.put(k.id, t);
        }
        log.info("Kiosk " + k.name + " (" + k.address + ") found; Echos can call it now, through port " + t.port);
    }

    private Closeable advertiseEcho(String name, int port) throws IOException {
        Map<String, String> txt = new LinkedHashMap<>();
        txt.put("name", name);
        return mdns.advertise(label(name), ECHO_SERVICE, port, txt);
    }

    private void readvertiseKiosk(KioskTwin t) {
        if (cfg.noAdvertise) return;
        closeQuietly(t.adv);
        try {
            t.adv = advertiseEcho(t.k.name, t.port);
        } catch (IOException e) {
            fail("advertising kiosk \"" + t.k.name + "\": " + e.getMessage());
        }
    }

    private void addEcho(Echo e, long now) throws IOException {
        EchoTwin t = new EchoTwin();
        t.e = e;
        t.id = standinId(e.name);
        t.name = e.name + cfg.nameSuffix;
        t.seen = now;
        int[] port = new int[1];
        t.srv = listen("t5:" + e.name.toLowerCase(Locale.ROOT), Ks.standin(t.id, t.name, cfg.version, port, auth, new StandinCalls(t)),
                Http.SMALL_BODY);
        t.port = port[0] = t.srv.port();
        if (!cfg.noAdvertise) {
            Map<String, String> txt = new LinkedHashMap<>();
            txt.put("id", t.id);
            txt.put("name", t.name);
            txt.put("version", cfg.version);
            txt.put("port", Integer.toString(t.port));
            txt.put("host", cfg.advertise);
            try {
                t.adv = mdns.advertise("ks-" + t.id, KIOSK_SERVICE, t.port, txt);
            } catch (IOException x) {
                t.srv.close();
                throw new IOException("advertising: " + x.getMessage());
            }
        }
        synchronized (this) {
            echos.put(e.name.toLowerCase(Locale.ROOT), t);
        }
        log.info("Echo " + e.name + " (" + e.address + ") found; kiosks can call it now, through port " + t.port);
    }

    /** Takes down the stand-ins of devices not heard from since before. */
    void forget(long before) {
        List<Runnable> gone = new ArrayList<>();
        synchronized (this) {
            for (Iterator<KioskTwin> it = kiosks.values().iterator(); it.hasNext(); ) {
                KioskTwin t = it.next();
                if (t.seen < before) {
                    it.remove();
                    log.info("Kiosk " + t.k.name + " gone quiet; its stand-in is down");
                    gone.add(() -> { closeQuietly(t.adv); t.srv.close(); });
                }
            }
            for (Iterator<EchoTwin> it = echos.values().iterator(); it.hasNext(); ) {
                EchoTwin t = it.next();
                if (t.seen < before) {
                    it.remove();
                    log.info("Echo " + t.e.name + " gone quiet; its stand-in is down");
                    gone.add(() -> { closeQuietly(t.adv); t.srv.close(); });
                }
            }
        }
        for (Runnable r : gone) r.run();
    }

    /** Takes every stand-in down and ends every call. */
    void close() {
        forget(Long.MAX_VALUE);
        List<Session> live;
        synchronized (this) {
            live = new ArrayList<>(calls.values());
        }
        for (Session s : live) s.inbox.offer(new Signal("hangup"));
    }

    static void closeQuietly(Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException | RuntimeException ignored) {}
    }

    /** Serves the port kept for key, or the first free one in the range, and remembers it. Bodies over bodyMost are refused. */
    private Http.Server listen(String key, Http.Handler h, int bodyMost) throws IOException {
        Long want;
        List<Long> taken = new ArrayList<>();
        synchronized (this) {
            want = ports.get(key);
            for (Map.Entry<String, Long> e : ports.entrySet()) if (!e.getKey().equals(key)) taken.add(e.getValue());
        }
        if (want != null) {
            try {
                return new Http.Server(cfg.listen, want.intValue(), h, pool, bodyMost);
            } catch (IOException ignored) {
            }
        }
        for (int port = cfg.portLow; port <= cfg.portHigh; port++) {
            if (taken.contains((long) port) || want != null && port == want) continue;
            Http.Server s;
            try {
                s = new Http.Server(cfg.listen, port, h, pool, bodyMost);
            } catch (IOException e) {
                continue;
            }
            synchronized (this) {
                ports.put(key, (long) port);
            }
            saveState();
            return s;
        }
        throw new IOException("no free port in " + cfg.portLow + "-" + cfg.portHigh);
    }

    private void loadState() {
        if (cfg.stateFile == null || !cfg.stateFile.isFile()) return;
        try {
            Map<String, Object> s = Json.object(Files.readAllBytes(cfg.stateFile.toPath()));
            Map<String, Long> p = new HashMap<>();
            for (Map.Entry<String, Object> e : Json.obj(s, "ports").entrySet()) {
                if (e.getValue() instanceof Number) p.put(e.getKey(), ((Number) e.getValue()).longValue());
            }
            synchronized (this) {
                ports = p;
            }
        } catch (IOException ignored) {
        }
    }

    private void saveState() {
        if (cfg.stateFile == null) return;
        Map<String, Object> s = new LinkedHashMap<>();
        synchronized (this) {
            s.put("ports", new LinkedHashMap<>(ports));
        }
        File tmp = new File(cfg.stateFile.getPath() + ".tmp");
        try {
            File dir = cfg.stateFile.getParentFile();
            if (dir != null) dir.mkdirs();
            try (FileOutputStream o = new FileOutputStream(tmp)) {
                o.write(Json.write(s).getBytes(StandardCharsets.UTF_8));
            }
            if (!tmp.renameTo(cfg.stateFile)) {
                cfg.stateFile.delete();
                tmp.renameTo(cfg.stateFile);
            }
        } catch (IOException ignored) {
        }
    }

    private void fail(String message) {
        log.warn(message);
        synchronized (this) {
            lastErr = message;
            lastAt = System.currentTimeMillis();
        }
    }

    /** One DNS label: letters, digits and dashes, at most 63 characters. */
    static String label(String s) {
        StringBuilder b = new StringBuilder();
        boolean dash = false;
        for (char c : s.toLowerCase(Locale.ROOT).toCharArray()) {
            if (c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
                b.append(c);
                dash = false;
            } else if (!dash && b.length() > 0) {
                b.append('-');
                dash = true;
            }
        }
        String out = b.toString().replaceAll("^-+|-+$", "");
        if (out.length() > 63) out = out.substring(0, 63).replaceAll("-+$", "");
        return out.isEmpty() ? "device" : out;
    }

    // ---- Status ----

    synchronized Map<String, Object> status() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("version", cfg.version);
        List<Map<String, Object>> ks = new ArrayList<>(), es = new ArrayList<>(), cs = new ArrayList<>();
        for (KioskTwin t : kiosks.values()) ks.add(twin(t.k.name, t.k.address, t.port, t.seen));
        for (EchoTwin t : echos.values()) es.add(twin(t.e.name, t.e.address, t.port, t.seen));
        for (Session c : calls.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", c.id); m.put("way", c.way); m.put("kiosk", c.kioskName); m.put("echo", c.echoName);
            m.put("answered", c.answered); m.put("started", c.started);
            cs.add(m);
        }
        Collections.sort(ks, (a, b) -> ((String) a.get("name")).compareTo((String) b.get("name")));
        Collections.sort(es, (a, b) -> ((String) a.get("name")).compareTo((String) b.get("name")));
        s.put("kiosks", ks);
        s.put("echos", es);
        s.put("calls", cs);
        if (!lastErr.isEmpty()) {
            s.put("last_error", lastErr);
            s.put("last_error_at", lastAt);
        }
        return s;
    }

    private static Map<String, Object> twin(String name, String address, int port, long seen) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name); m.put("address", address); m.put("standin_port", port); m.put("seen", seen);
        return m;
    }

    synchronized int kioskCount() { return kiosks.size(); }

    synchronized int echoCount() { return echos.size(); }

    synchronized int callCount() { return calls.size(); }

    synchronized String lastError() { return lastErr; }

    // ---- Calls ----

    private static final String WAY_TO_ECHO = "kiosk to Echo", WAY_TO_KIOSK = "Echo to kiosk",
            WAY_ANNOUNCE_TO_KIOSK = "Echo announcement", WAY_ANNOUNCE_TO_ECHO = "kiosk announcement";

    private synchronized void addCall(Session s) { calls.put(s.id, s); }

    private synchronized void dropCall(Session s) { calls.remove(s.id); }

    private synchronized Session call(String id) { return calls.get(id); }

    private static String newCallId() { return Crypto.hex(Crypto.random(12)); }

    /** One stand-in kiosk's side of {@link Ks.Calls}. */
    private final class StandinCalls implements Ks.Calls {
        final EchoTwin t;
        StandinCalls(EchoTwin t) { this.t = t; }

        @Override public String ring(String call, String kind, Ks.Peer from, String remote) {
            if ("broadcast".equals(kind)) return kioskAnnouncesToEcho(t, call, from);
            return kioskCallsEcho(t, call, kind, from, remote);
        }

        @Override public boolean signal(String call, String action) {
            Session s = call(call);
            if (s == null) return false;
            s.inbox.offer(new Signal(action));
            return true;
        }

        @Override public boolean hasCall(String call) { return call(call) != null; }

        @Override public void audio(String call, WebSocket ws) {
            Session s = call(call);
            if (s == null) ws.close(); else s.inbox.offer(ws);
        }
    }

    /** Tells the kiosk in a call what happened, at its call port. */
    private boolean signalKiosk(Session s, String action) {
        try {
            if (s.endpoint == 0) s.endpoint = ksc.identity(s.kioskHost, s.kioskAdmin).endpointPort;
            ksc.signal(s.kioskHost, s.endpoint, s.id, s.fromId, action);
            return true;
        } catch (IOException e) {
            fail("telling " + s.kioskName + " \"" + action + "\": " + e.getMessage());
            return false;
        }
    }

    private static boolean ends(Object ev) {
        return ev instanceof Signal && ("cancel".equals(((Signal) ev).action) || "hangup".equals(((Signal) ev).action));
    }

    /** A kiosk calling an Echo's stand-in: the bridge calls the Echo, and its first answer is what the kiosk is told. */
    private String kioskCallsEcho(EchoTwin t, String callId, String kind, Ks.Peer from, String remote) {
        Echo echo = t.e;
        String caller = from.name.isEmpty() ? "Kiosk" : from.name;
        String tag = " (" + caller + " to " + echo.name + ")";
        if (!"call".equals(kind)) {
            log.info("A call of an unknown kind, " + kind + ", turned away" + tag);
            return "refused";
        }
        Session s = new Session();
        s.id = callId;
        s.way = WAY_TO_ECHO;
        s.kioskName = caller;
        s.echoName = echo.name;
        s.kioskHost = from.address.isEmpty() || from.address.equals("127.0.0.1") ? remote : from.address;
        s.kioskAdmin = from.port;
        s.fromId = t.id;
        try {
            s.link = T5Link.dial(echo.address, echo.port, t5key, caller, s.inbox);
        } catch (Sealed.KeyException e) {
            fail(echo.name + " refused the call: the house word does not match");
            return "off";
        } catch (IOException e) {
            fail("calling " + echo.name + ": " + e.getMessage());
            return "off";
        }
        Object first;
        try {
            first = s.inbox.poll(Ks.REQUEST_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            first = null;
        }
        if (first == T5Link.GONE) {
            fail(echo.name + " hung up before ringing; check the house word");
            return "off";
        }
        if (!(first instanceof Byte)) {
            s.link.close();
            fail(echo.name + " did not answer the call in time");
            return "off";
        }
        byte m = (Byte) first;
        if (m != T5Link.RINGING) {
            s.link.close();
            String status = m == T5Link.BUSY ? "busy" : m == T5Link.NOT_NOW ? "dnd" : "refused";
            log.info("The Echo said " + status + tag);
            return status;
        }
        addCall(s);
        log.info("Ringing" + tag);
        pool.execute(() -> runKioskToEcho(s));
        return "ringing";
    }

    private void runKioskToEcho(Session s) {
        String tag = " (" + s.kioskName + " to " + s.echoName + ")";
        try {
            long ringUntil = System.currentTimeMillis() + RING_MS + 5000;
            while (true) {
                Object ev = s.inbox.poll(Math.max(1, ringUntil - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                if (ev == null) {
                    s.link.close();
                    signalKiosk(s, "missed");
                    return;
                }
                if (ev instanceof Byte) {
                    byte m = (Byte) ev;
                    if (m == T5Link.ANSWER) break;
                    if (m == T5Link.DECLINE || m == T5Link.BUSY || m == T5Link.NOT_NOW) {
                        String action = System.currentTimeMillis() - s.started >= RING_MS - 2000 ? "missed" : "decline";
                        s.link.close();
                        log.info("Not answered: " + action + tag);
                        signalKiosk(s, action);
                        return;
                    }
                } else if (ev == T5Link.GONE) {
                    log.info("The Echo dropped the call while ringing" + tag);
                    signalKiosk(s, "decline");
                    return;
                } else if (ends(ev)) {
                    log.info("The kiosk gave up" + tag);
                    s.link.close();
                    return;
                }
            }
            s.answered = true;
            s.link.talk();
            Relay rl = new Relay(s.link, cfg.toEchoDb, cfg.toKioskDb, cfg.quietDbfs, s.inbox, pool);
            rl.start(); // the Echo hears silence until the kiosk's socket is up
            if (!signalKiosk(s, "answer")) {
                rl.close();
                return;
            }
            log.info("Answered" + tag);
            long socketUntil = System.currentTimeMillis() + SOCKET_WAIT_MS;
            while (!rl.done()) {
                Object ev = s.inbox.poll(Math.max(1, socketUntil - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                if (ev == null) {
                    rl.end(Relay.BRIDGE, "the kiosk did not open the audio socket");
                } else if (ev instanceof WebSocket) {
                    rl.attach((WebSocket) ev);
                    break;
                } else if (ends(ev)) {
                    rl.end(Relay.KIOSK, "the kiosk hung up");
                }
            }
            carry(s, rl, tag);
        } catch (InterruptedException e) {
            if (s.link != null) s.link.close();
        } finally {
            dropCall(s);
        }
    }

    /** A request on a kiosk's stand-in TECHO5 device: an Echo calling or announcing to that kiosk. */
    private void serveEchoCall(KioskTwin t, Http.Request r) throws IOException {
        if (r.path.equals(T5Announce.PATH)) {
            echoAnnounces(t, r);
            return;
        }
        if (!r.path.equals(T5Link.PATH)) {
            r.text(404, "not found");
            return;
        }
        if (!r.header("upgrade").equalsIgnoreCase(T5Link.PROTOCOL)) {
            r.text(400, "an intercom call only");
            return;
        }
        r.taken = true;
        Session s = new Session();
        T5Link.Accepted a;
        try {
            a = T5Link.accept(r, t5key, s.inbox);
        } catch (Sealed.KeyException e) {
            fail("An Echo at " + r.remoteHost() + " called with a different house word");
            return;
        } catch (IOException e) {
            fail("An Echo's call to " + t.k.name + ": " + e.getMessage());
            return;
        }
        echoCallsKiosk(t, s, a.link, a.caller, r.remoteHost());
    }

    /** The Echo a call came from: by the name it gave, else by its address. */
    private synchronized EchoTwin echoTwinFor(String name, String address) {
        EchoTwin t = echos.get(name.toLowerCase(Locale.ROOT));
        if (t != null) return t;
        for (EchoTwin e : echos.values()) if (e.e.address.equals(address)) return e;
        return null;
    }

    private Ks.Peer peerFor(EchoTwin et) {
        Ks.Peer p = new Ks.Peer();
        p.id = et.id;
        p.name = et.name;
        p.address = cfg.advertise;
        p.port = et.port;
        p.version = cfg.version;
        return p;
    }

    /** Why a kiosk will not take a call or broadcast from the bridge, or null when it will. */
    private String refusal(Kiosk kiosk, Ks.Identity id) {
        if (!id.enabled) return "dnd:intercom off on the kiosk";
        if (!ksc.keyMatches(id)) {
            fail(kiosk.name + " has a different intercom key");
            return "decline:intercom key mismatch";
        }
        if (id.tls) {
            fail(kiosk.name + " has intercom encryption on, which the bridge does not speak yet");
            return "decline:kiosk wants TLS";
        }
        if (id.dnd) return "dnd:kiosk in do not disturb";
        return null;
    }

    private void echoCallsKiosk(KioskTwin t, Session s, T5Link link, String caller, String remote) {
        Kiosk kiosk = t.k;
        String tag = " (" + caller + " to " + kiosk.name + ")";
        try {
            EchoTwin et = echoTwinFor(caller, remote);
            if (et == null) {
                fail(caller + " called " + kiosk.name + ", but the bridge has not found that Echo yet");
                refuse(link, T5Link.DECLINE, "unknown Echo", tag);
                return;
            }
            Ks.Identity id;
            try {
                id = ksc.identity(kiosk.address, kiosk.adminPort);
            } catch (IOException e) {
                fail("reading " + kiosk.name + ": " + e.getMessage());
                refuse(link, T5Link.DECLINE, "kiosk unreachable", tag);
                return;
            }
            String no = refusal(kiosk, id);
            if (no != null) {
                refuse(link, no.startsWith("dnd") ? T5Link.NOT_NOW : T5Link.DECLINE, no.substring(no.indexOf(':') + 1), tag);
                return;
            }
            s.id = newCallId();
            s.way = WAY_TO_KIOSK;
            s.kioskName = kiosk.name;
            s.echoName = et.e.name;
            s.link = link;
            s.kioskHost = kiosk.address;
            s.kioskAdmin = kiosk.adminPort;
            s.endpoint = id.endpointPort;
            s.fromId = et.id;
            addCall(s); // before ringing: a kiosk that answers by itself answers at once
            String status;
            try {
                status = ksc.call(kiosk.address, s.endpoint, s.id, "call", peerFor(et));
            } catch (IOException e) {
                fail("calling " + kiosk.name + ": " + e.getMessage());
                refuse(link, T5Link.DECLINE, "call failed", tag);
                return;
            }
            switch (status) {
                case "ringing": case "auto": case "listening": break;
                case "busy": refuse(link, T5Link.BUSY, status, tag); return;
                case "dnd": case "off": case "refused": refuse(link, T5Link.NOT_NOW, status, tag); return;
                default:
                    fail(kiosk.name + " refused the call: " + status);
                    refuse(link, T5Link.DECLINE, status, tag);
                    return;
            }
            try { link.say(T5Link.RINGING); } catch (IOException ignored) {}
            log.info("Ringing" + tag);
            long ringUntil = System.currentTimeMillis() + RING_MS;
            while (true) {
                Object ev = s.inbox.poll(Math.max(1, ringUntil - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                if (ev == null) {
                    signalKiosk(s, "cancel");
                    refuse(link, T5Link.DECLINE, "no answer", tag);
                    return;
                }
                if (ev == T5Link.GONE) {
                    log.info("The Echo gave up" + tag);
                    signalKiosk(s, "cancel");
                    return;
                }
                if (ev instanceof Signal) {
                    String a = ((Signal) ev).action;
                    if (a.equals("answer")) break;
                    if (a.equals("decline") || a.equals("missed") || a.equals("cancel") || a.equals("hangup")) {
                        refuse(link, T5Link.DECLINE, a, tag);
                        return;
                    }
                }
            }
            s.answered = true;
            try {
                link.say(T5Link.ANSWER);
            } catch (IOException e) {
                signalKiosk(s, "hangup");
                link.close();
                return;
            }
            link.talk();
            Relay rl = new Relay(link, cfg.toEchoDb, cfg.toKioskDb, cfg.quietDbfs, s.inbox, pool);
            rl.start();
            log.info("Answered" + tag);
            try {
                rl.attach(ksc.dialAudio(kiosk.address, s.endpoint, s.id, et.id));
            } catch (IOException e) {
                fail("opening the audio socket to " + kiosk.name + ": " + e.getMessage());
                rl.end(Relay.BRIDGE, "no audio socket");
            }
            carry(s, rl, tag);
        } catch (InterruptedException e) {
            link.close();
        } finally {
            dropCall(s);
        }
    }

    private void refuse(T5Link link, byte m, String why, String tag) {
        log.info("Call not placed: " + why + tag);
        try { link.say(m); } catch (IOException ignored) {}
        link.close();
    }

    /** Waits out an answered call, then hangs up both sides. */
    private void carry(Session s, Relay rl, String tag) throws InterruptedException {
        long limit = System.currentTimeMillis() + cfg.maxCallMs;
        while (!rl.done()) {
            Object ev = s.inbox.poll(1, TimeUnit.SECONDS);
            if (ends(ev)) rl.end(Relay.KIOSK, "the kiosk hung up");
            else if (System.currentTimeMillis() > limit) rl.end(Relay.BRIDGE, "maximum call length");
            else if (cfg.silenceHangupMs > 0 && rl.quietMs() >= cfg.silenceHangupMs) {
                rl.end(Relay.BRIDGE, "nobody spoke for " + cfg.silenceHangupMs / 1000 + " s");
            }
        }
        rl.close();
        if (!Relay.KIOSK.equals(rl.by)) signalKiosk(s, "hangup");
        log.info("Call ended by the " + rl.by + ": " + rl.why + ", after " + (System.currentTimeMillis() - s.started) / 1000 + " s" + tag);
    }

    // ---- Announcements ----
    // A TECHO5 device announces by sending its recorded voice to every device it knows, the kiosks'
    // stand-ins among them: each is played on its kiosk as a Kiosk Satellite broadcast. A kiosk's
    // Announce to all reaches each Echo's stand-in as a broadcast: the bridge gathers it and sends it on
    // to the Echo as a TECHO5 announcement once the kiosk has finished, since that is a recording.

    private void echoAnnounces(KioskTwin t, Http.Request r) throws IOException {
        T5Announce.Message m = ann.receive(r);
        Kiosk kiosk = t.k;
        if (m == null) {
            fail("An announcement for " + kiosk.name + " from " + r.remoteHost() + " was refused (a different house word, or a clock far off)");
            return;
        }
        if (!m.kind.isEmpty()) return; // a reminder; a kiosk has no use for it
        if (m.voice.length == 0) {
            log.info("Not carried to " + kiosk.name + ": an announcement of words only has no voice to play");
            return;
        }
        String remote = r.remoteHost();
        pool.execute(() -> playOnKiosk(kiosk, m, remote));
    }

    /** Plays an Echo's announcement on a kiosk as a broadcast. */
    private void playOnKiosk(Kiosk kiosk, T5Announce.Message m, String remote) {
        String tag = " (" + m.from + " announcing on " + kiosk.name + ")";
        EchoTwin et = echoTwinFor(m.from, remote);
        if (et == null) {
            fail(m.from + " announced, but the bridge has not found that Echo yet");
            return;
        }
        Ks.Identity id;
        try {
            id = ksc.identity(kiosk.address, kiosk.adminPort);
        } catch (IOException e) {
            fail("reading " + kiosk.name + ": " + e.getMessage());
            return;
        }
        String no = refusal(kiosk, id);
        if (no != null) {
            log.info("Not played: " + no.substring(no.indexOf(':') + 1) + tag);
            return;
        }
        Session s = new Session();
        s.id = newCallId();
        s.way = WAY_ANNOUNCE_TO_KIOSK;
        s.kioskName = kiosk.name;
        s.echoName = et.e.name;
        s.kioskHost = kiosk.address;
        s.kioskAdmin = kiosk.adminPort;
        s.endpoint = id.endpointPort;
        s.fromId = et.id;
        addCall(s);
        WebSocket ws = null;
        try {
            String status = ksc.call(kiosk.address, s.endpoint, s.id, "broadcast", peerFor(et));
            if (!status.equals("listening") && !status.equals("auto") && !status.equals("ringing")) {
                log.info("Not played: the kiosk said " + status + tag);
                return;
            }
            try {
                ws = ksc.dialAudio(kiosk.address, s.endpoint, s.id, et.id);
            } catch (IOException e) {
                fail("opening the audio socket to " + kiosk.name + ": " + e.getMessage());
                signalKiosk(s, "hangup");
                return;
            }
            WebSocket sock = ws;
            pool.execute(() -> { // the kiosk's side: Dismiss on its card ends the broadcast
                try {
                    while (true) sock.read();
                } catch (IOException e) {
                    s.inbox.offer(new Signal("hangup"));
                }
            });
            ws.sendText("{\"type\":\"talk\",\"on\":true}");
            byte[] voice = m.voice.clone();
            Relay.applyGain(voice, voice.length, Relay.gain(cfg.toKioskDb));
            boolean dismissed = false;
            long next = System.currentTimeMillis();
            for (int i = 0; i < voice.length && !dismissed; i += Ks.FRAME_BYTES) {
                byte[] frame = new byte[Ks.FRAME_BYTES];
                System.arraycopy(voice, i, frame, 0, Math.min(Ks.FRAME_BYTES, voice.length - i));
                ws.send(WebSocket.BINARY, frame);
                next += 80;
                Object ev = s.inbox.poll(Math.max(1, next - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                dismissed = ends(ev);
            }
            if (!dismissed) {
                ws.sendText("{\"type\":\"end\"}");
                signalKiosk(s, "hangup");
            }
            log.info("Announcement played, " + voice.length / 32000 + " s" + (dismissed ? ", dismissed" : "") + tag);
        } catch (IOException e) {
            fail("announcing on " + kiosk.name + ": " + e.getMessage());
        } catch (InterruptedException ignored) {
        } finally {
            if (ws != null) ws.close();
            dropCall(s);
        }
    }

    /** A kiosk's Announce to all reaching an Echo's stand-in. */
    private String kioskAnnouncesToEcho(EchoTwin t, String callId, Ks.Peer from) {
        Session s = new Session();
        s.id = callId;
        s.way = WAY_ANNOUNCE_TO_ECHO;
        s.kioskName = from.name.isEmpty() ? "Kiosk" : from.name;
        s.echoName = t.e.name;
        addCall(s);
        Echo echo = t.e;
        pool.execute(() -> gatherForEcho(s, echo));
        return "listening";
    }

    /** Takes a kiosk's broadcast off its audio socket and, once it ends, sends it to the Echo. */
    private void gatherForEcho(Session s, Echo echo) {
        String tag = " (" + s.kioskName + " announcing on " + echo.name + ")";
        WebSocket ws = null;
        try {
            Object ev = s.inbox.poll(SOCKET_WAIT_MS, TimeUnit.MILLISECONDS);
            if (!(ev instanceof WebSocket)) {
                if (ev == null) log.info("The kiosk did not open the audio socket" + tag);
                return;
            }
            ws = (WebSocket) ev;
            byte[] voice = new byte[T5Announce.MAX_BYTES];
            int have = 0;
            long until = System.currentTimeMillis() + ANNOUNCE_LISTEN_MS;
            while (true) {
                long left = until - System.currentTimeMillis();
                if (left <= 0) break;
                ws.setReadTimeout((int) left);
                WebSocket.Message m;
                try {
                    m = ws.read();
                } catch (IOException e) {
                    break;
                }
                if (m.kind == WebSocket.BINARY) {
                    int n = Math.min(m.data.length, voice.length - have);
                    System.arraycopy(m.data, 0, voice, have, n);
                    have += n;
                } else if ("end".equals(Json.str(Json.object(m.data), "type"))) {
                    break;
                }
            }
            ws.close();
            have &= ~1;
            if (have == 0) {
                log.info("Nothing was said" + tag);
                return;
            }
            T5Announce.Message out = new T5Announce.Message();
            out.from = s.kioskName;
            out.voice = java.util.Arrays.copyOf(voice, have);
            Relay.applyGain(out.voice, have, Relay.gain(cfg.toEchoDb));
            ann.send(echo.address, echo.port, out);
            log.info("Announcement passed on, " + have / 32000 + " s" + tag);
        } catch (IOException e) {
            fail("announcing on " + echo.name + ": " + e.getMessage());
        } catch (InterruptedException ignored) {
        } finally {
            if (ws != null) ws.close();
            dropCall(s);
        }
    }
}
