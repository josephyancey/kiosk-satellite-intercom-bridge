package dev.yancey.intercombridge;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Looks for services by listening to mDNS itself, the way Kiosk Satellite finds its fleet, rather than
 * through Android's mDNS service. Some Android builds' service hears little of what Kiosk Satellite
 * announces, though the same packets reach the device, and the service limits and can jam lookups.
 *
 * One socket is bound to the mDNS group's address, so it hears only what is sent to the group and never
 * takes a reply sent straight to the device's mDNS port, which is Android's or Kiosk Satellite's. Queries
 * go out from a port of its own, where responders send their answers straight back. Advertising stays
 * with the given Mdns, which also does the looking if the group cannot be joined.
 *
 * What it advertises it also announces to the group itself, every ANNOUNCE_MS, as Kiosk Satellite does:
 * Kiosk Satellite drops a kiosk it has not heard from in 100 seconds, and Android's mDNS service
 * announces a service once, when it is registered, and after that only answers questions. The records
 * announced are the ones Android's service gives when asked, byte for byte: it holds the same names,
 * and would take any other SRV or TXT for them as a conflict and rename the service.
 */
final class GroupMdns implements Mdns {
    static final String GROUP = "224.0.0.251";
    static final int PORT = 5353;
    private static final int TYPE_A = 1, TYPE_PTR = 12, TYPE_TXT = 16, TYPE_SRV = 33, CLASS_IN = 1;
    private static final long FOLLOW_UP_MS = 500; // how often a look asks for what it still lacks
    private static final long ASK_AGAIN_MS = 1000; // the soonest the same question goes out again
    static final long ANNOUNCE_MS = 30000; // three chances inside Kiosk Satellite's 100 seconds
    static final int RECORD_TTL = 4500, HOST_TTL = 120; // Kiosk Satellite's, the mDNS conventions
    private static final long ANSWER_MS = 1000; // how long Android's service has to answer before an announcement

    private final Mdns fallback;
    private final InetAddress group;
    private final int port;
    private final Cache cache = new Cache();
    private final Map<String, String> looks = new ConcurrentHashMap<>(); // type to how its last look went
    private final Map<String, Boolean> complete = new ConcurrentHashMap<>();
    private final Map<String, Long> asked = new HashMap<>(); // question to when it last went out
    private MulticastSocket listen, ask;
    private String notListening = ""; // why looks go through the fallback, when they do
    private boolean closed;
    private final String self; // this device's address, which Android's service answers from
    private final long announceMs;
    private final ScheduledThreadPoolExecutor announcer;
    private final Map<Ad, Boolean> ads = new ConcurrentHashMap<>();
    private volatile String announced = ""; // how the last announcement went, for the status page

    GroupMdns(Mdns fallback, ThreadFactory threads, String address) {
        this(fallback, threads, address, GROUP, PORT, ANNOUNCE_MS);
    }

    GroupMdns(Mdns fallback, ThreadFactory threads, String address, String group, int port, long announceMs) {
        this.fallback = fallback;
        this.port = port;
        this.announceMs = announceMs;
        this.self = address == null ? "" : address.trim();
        announcer = new ScheduledThreadPoolExecutor(1, threads);
        announcer.scheduleWithFixedDelay(() -> {
            for (Ad ad : ads.keySet()) ask(ad);
            sleepQuietly(ANSWER_MS);
            for (Ad ad : ads.keySet()) announce(ad);
        }, announceMs, announceMs, TimeUnit.MILLISECONDS);
        InetAddress g = null;
        try {
            g = InetAddress.getByName(group);
            listen = new MulticastSocket(new InetSocketAddress(g, port));
            if (join(listen, g, port) == 0) listen.joinGroup(g);
            ask = new MulticastSocket(0);
            ask.setTimeToLive(255);
            receiveOn(listen, threads);
            receiveOn(ask, threads);
        } catch (IOException | RuntimeException e) {
            notListening = "could not listen to mDNS (" + e + "); Android's mDNS service looks instead";
            close(listen);
            close(ask);
            listen = ask = null;
        }
        this.group = g;
    }

    /** Joins the group on every network that can carry it; the number joined, or already joined. */
    static int join(MulticastSocket s, InetAddress group, int port) {
        int n = 0;
        try {
            for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!nic.isUp() || nic.isLoopback() || !nic.supportsMulticast()) continue;
                boolean v4 = false;
                for (InetAddress a : Collections.list(nic.getInetAddresses())) v4 |= a instanceof Inet4Address;
                if (!v4) continue;
                try {
                    s.joinGroup(new InetSocketAddress(group, port), nic);
                    n++;
                } catch (IOException e) {
                    if (String.valueOf(e.getMessage()).contains("already")) n++; // joined before, as on a rejoin
                }
            }
        } catch (SocketException | RuntimeException ignored) {
        }
        return n;
    }

    private void receiveOn(MulticastSocket s, ThreadFactory threads) {
        threads.newThread(() -> {
            byte[] buf = new byte[9000];
            while (!s.isClosed()) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                } catch (IOException e) {
                    if (s.isClosed()) return;
                    try {
                        Thread.sleep(FOLLOW_UP_MS); // the network is down, say; no need to spin on it
                    } catch (InterruptedException stop) {
                        return;
                    }
                    continue;
                }
                try {
                    cache.handle(p.getData(), p.getLength(), p.getAddress().getHostAddress(), System.currentTimeMillis());
                } catch (RuntimeException e) {
                    // One packet's surprise must not leave the listener deaf to the rest.
                }
            }
        }).start();
    }

    private static void close(Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException ignored) {}
    }

    synchronized void close() {
        closed = true;
        close(listen);
        close(ask);
        // Goodbyes for what is still advertised: the periodic announcement ends, but they still go.
        for (Ad ad : new ArrayList<>(ads.keySet())) {
            ads.remove(ad);
            goodbye(ad);
        }
        announcer.shutdown();
    }

    private synchronized boolean listening() {
        return listen != null && !closed;
    }

    @Override
    public List<Service> browse(String type, long lookMs) throws IOException, InterruptedException {
        if (!listening()) {
            if (closed) throw new IOException("mDNS is closed");
            return fallback.browse(type, lookMs);
        }
        join(listen, group, port); // after Wi-Fi comes back, the group has to be joined again
        String domain = type + ".local";
        long end = System.currentTimeMillis() + lookMs, again = System.currentTimeMillis() + lookMs / 3;
        boolean secondAsk = false;
        send(question(domain, TYPE_PTR));
        while (true) {
            long now = System.currentTimeMillis();
            if (now >= end) break;
            // Follow-ups are worth a try only: what was heard counts even if one cannot go out.
            try {
                if (!secondAsk && now >= again) {
                    secondAsk = true;
                    send(question(domain, TYPE_PTR)); // in case the first question or its answers were lost
                }
                for (String[] q : cache.missing(domain, now)) send(q);
            } catch (IOException e) {
                if (!listening()) throw e;
            }
            Thread.sleep(Math.min(FOLLOW_UP_MS, end - now));
        }
        Cache.Look look = cache.look(domain, System.currentTimeMillis());
        StringBuilder note = new StringBuilder(look.found + " found, " + look.services.size() + " resolved");
        if (look.found > look.complete) note.append(", ").append(look.found - look.complete).append(" without all their records");
        if (look.gone > 0) note.append(", ").append(look.gone).append(" not answering");
        looks.put(type, note.toString());
        complete.put(type, look.found == look.complete && look.gone == 0);
        return look.services;
    }

    private static String[] question(String name, int type) {
        return new String[] {name, Integer.toString(type)};
    }

    /** Asks a question, unless it went out within ASK_AGAIN_MS. Responders answer to the asking port. */
    private void send(String[] q) throws IOException {
        String key = q[1] + " " + q[0].toLowerCase(Locale.ROOT);
        long now = System.currentTimeMillis();
        MulticastSocket s;
        synchronized (this) {
            Long last = asked.get(key);
            if (last != null && now - last < ASK_AGAIN_MS) return;
            asked.put(key, now);
            if (asked.size() > 512) asked.values().removeIf(t -> now - t > ASK_AGAIN_MS);
            s = ask;
        }
        if (s == null) throw new IOException("mDNS is closed");
        byte[] p = Cache.query(q[0], Integer.parseInt(q[1]));
        try {
            s.send(new DatagramPacket(p, p.length, group, port));
        } catch (IOException e) {
            throw new IOException("mDNS question for " + q[0] + ": " + e.getMessage());
        }
    }

    @Override
    public boolean lastLookComplete(String type) {
        return listening() ? complete.getOrDefault(type, false) : fallback.lastLookComplete(type);
    }

    @Override
    public Map<String, Object> diagnostics() {
        Map<String, Object> d = new LinkedHashMap<>(listening() ? looks : fallback.diagnostics());
        if (!listening() && !notListening.isEmpty()) d.put("listener", notListening);
        if (!announced.isEmpty()) d.put("announcing", announced);
        return d;
    }

    /** One service advertised here, as announced to the group. */
    static final class Ad {
        final String instance, type;
        final int port;
        final List<String> full; // its name's labels
        volatile byte[] goodbye; // ends what was last announced, once anything was

        Ad(String instance, String type, int port) {
            this.instance = instance;
            this.type = type;
            this.port = port;
            full = new ArrayList<>();
            full.add(instance);
            full.addAll(Cache.labels(type + ".local"));
        }
    }

    @Override
    public Closeable advertise(String instance, String type, int port, Map<String, String> txt) throws IOException {
        Closeable registered = fallback.advertise(instance, type, port, txt); // so questions are answered too
        Ad ad = new Ad(instance, type, port);
        ads.put(ad, true);
        // Android's service announced it on registering; the first of these follows a few seconds on.
        try {
            announcer.execute(() -> ask(ad));
            announcer.schedule(() -> announce(ad), ANSWER_MS * 2, TimeUnit.MILLISECONDS);
        } catch (RuntimeException shutDown) {
            // Closed already: nothing more is announced.
        }
        return () -> {
            boolean was = ads.remove(ad) != null;
            registered.close(); // Android's goodbye first, so its service does not defend the name against ours
            if (was) goodbye(ad);
        };
    }

    /** Asks Android's service for ad's SRV and TXT, and its host's address, which come back to this listener. */
    private void ask(Ad ad) {
        if (!listening()) return;
        String full = ad.instance + "." + ad.type + ".local";
        try {
            send(question(full, TYPE_SRV));
            send(question(full, TYPE_TXT));
            Cache.Held h = cache.held(ad.full, self, System.currentTimeMillis());
            if (h != null) send(question(String.join(".", h.target), TYPE_A));
        } catch (IOException e) {
            announced = "asking for " + ad.instance + " failed: " + e.getMessage();
        }
    }

    /** Announces ad's records as Android's service last gave them; nothing until it has. */
    private void announce(Ad ad) {
        if (!ads.containsKey(ad)) return;
        Cache.Held h = cache.held(ad.full, self, System.currentTimeMillis());
        if (h == null || h.port != ad.port) {
            announced = "Android's mDNS service did not answer for " + ad.instance;
            return;
        }
        ad.goodbye = response(ad, h, 0, 0);
        sendResponse(response(ad, h, RECORD_TTL, HOST_TTL), ad.instance);
    }

    /** A goodbye, sent from the announcer's thread, since the caller's may be one that must not use the network. */
    private void goodbye(Ad ad) {
        byte[] p = ad.goodbye;
        if (p == null) return; // never announced here; Android's service says its own goodbye
        try {
            announcer.execute(() -> sendResponse(p, ad.instance));
        } catch (RuntimeException shutDown) {
            // Android's service still says its own.
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Sends a response to the group from the mDNS port, as responders expect of one. The socket is held
     * only for the send, so a reply sent straight to the device's mDNS port is not taken from Android or
     * Kiosk Satellite; when the port cannot be had, it goes from a port of its own.
     */
    private void sendResponse(byte[] p, String what) {
        if (group == null) return;
        DatagramPacket packet = new DatagramPacket(p, p.length, group, port);
        String every = "every " + announceMs / 1000 + " s, " + ads.size() + " now";
        try (MulticastSocket s = new MulticastSocket(null)) {
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(port));
            s.setTimeToLive(255);
            s.send(packet);
            announced = every;
        } catch (IOException | RuntimeException fromPort) {
            try (MulticastSocket s = new MulticastSocket(0)) {
                s.setTimeToLive(255);
                s.send(packet);
                // Most responders ignore a response from any port but 5353; Kiosk Satellite takes it.
                announced = every + ", from a port of its own, so only kiosks heed them (" + fromPort.getMessage() + ")";
            } catch (IOException | RuntimeException e) {
                announced = "announcing " + what + " failed: " + e.getMessage();
            }
        }
    }

    /** An unsolicited response with ad's PTR, SRV and TXT as held, and its host's address unless it is a goodbye. */
    static byte[] response(Ad ad, Cache.Held h, int ttl, int hostTtl) {
        boolean withAddress = h.address != null && hostTtl > 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        u16(out, 0);
        u16(out, 0x8400); // an authoritative response
        u16(out, 0);
        u16(out, withAddress ? 4 : 3);
        u16(out, 0);
        u16(out, 0);
        List<String> full = ad.full;
        // The PTR is shared, so without the cache-flush bit; the rest are this device's alone.
        record(out, Cache.labels(ad.type + ".local"), TYPE_PTR, CLASS_IN, ttl, name(full));
        ByteArrayOutputStream srv = new ByteArrayOutputStream();
        u16(srv, h.priority);
        u16(srv, h.weight);
        u16(srv, h.port);
        byte[] target = name(h.target);
        srv.write(target, 0, target.length);
        record(out, full, TYPE_SRV, 0x8000 | CLASS_IN, hostTtl, srv.toByteArray());
        record(out, full, TYPE_TXT, 0x8000 | CLASS_IN, ttl, h.txt);
        if (withAddress) record(out, h.target, TYPE_A, 0x8000 | CLASS_IN, hostTtl, h.address);
        return out.toByteArray();
    }

    private static void record(ByteArrayOutputStream out, List<String> name, int type, int cls, long ttl, byte[] data) {
        byte[] n = name(name);
        out.write(n, 0, n.length);
        u16(out, type);
        u16(out, cls);
        u16(out, (int) (ttl >> 16));
        u16(out, (int) ttl);
        u16(out, data.length);
        out.write(data, 0, data.length);
    }

    private static byte[] name(List<String> labels) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String l : labels) {
            byte[] b = l.getBytes(StandardCharsets.UTF_8);
            out.write(Math.min(b.length, 63));
            out.write(b, 0, Math.min(b.length, 63));
        }
        out.write(0);
        return out.toByteArray();
    }

    private static void u16(ByteArrayOutputStream out, int v) {
        out.write(v >> 8 & 255);
        out.write(v & 255);
    }

    /** The four bytes of a dotted IPv4 address, or null for anything else. */
    static byte[] ipv4(String a) {
        if (a == null) return null;
        String[] parts = a.trim().split("\\.", -1);
        if (parts.length != 4) return null;
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (!parts[i].matches("[0-9]{1,3}")) return null;
            int v = Integer.parseInt(parts[i]);
            if (v > 255) return null;
            out[i] = (byte) v;
        }
        return out;
    }

    /**
     * The records heard, each until its time to live runs out or a goodbye ends it. Bounded, since anyone
     * on the network can send them.
     */
    static final class Cache {
        private static final int MOST = 1024; // records of each kind kept
        private static final long LONGEST_MS = 3 * 3600000L; // the longest a record is believed
        static final long GONE_MS = 10000; // asked this long for an instance's port, unanswered, it has gone

        private static final class Ptr { final String instance; final long until; Ptr(String i, long u) { instance = i; until = u; } }
        private static final class Srv { final String target, from; final int port, priority, weight; final List<String> heard; final long until;
            Srv(String t, int p, String f, long u, int pr, int w, List<String> h) { target = t; port = p; from = f; until = u; priority = pr; weight = w; heard = h; } }
        private static final class Txt { final Map<String, String> txt; final byte[] raw; final long until;
            Txt(Map<String, String> t, byte[] r, long u) { txt = t; raw = r; until = u; } }
        private static final class A { final String address; final long until; A(String a, long u) { address = a; until = u; } }

        private final Map<String, Map<String, Ptr>> ptrs = new HashMap<>(); // domain to instance name to record
        private final Map<String, Srv> srvs = new HashMap<>(); // full name to record
        private final Map<String, Txt> txts = new HashMap<>();
        private final Map<String, A> as = new HashMap<>(); // host to record
        private final Map<String, Long> unanswered = new HashMap<>(); // full name to when its port was first asked
        private int ptrCount;
        private long purgedAt = Long.MIN_VALUE;

        static final class Look {
            final List<Service> services = new ArrayList<>();
            int found, complete, gone;
        }

        /** A packet heard from address from; anything but a well-formed response adds nothing. */
        synchronized void handle(byte[] data, int length, String from, long now) {
            try {
                read(data, length, from, now);
            } catch (IllegalArgumentException ignored) {
                // Cut short or malformed: dropped whole.
            }
        }

        private void read(byte[] data, int length, String from, long now) {
            Reader r = new Reader(data, length);
            r.u16();
            int flags = r.u16();
            if ((flags & 0x8000) == 0 || (flags & 0x000f) != 0) return; // a query, or an error
            int qd = r.u16(), an = r.u16(), ns = r.u16(), ar = r.u16();
            for (int i = 0; i < qd; i++) {
                r.name();
                r.skip(4);
            }
            List<Object[]> records = new ArrayList<>();
            for (int i = 0; i < an + ns + ar; i++) {
                List<String> name = r.name();
                int type = r.u16(), cls = r.u16() & 0x7fff;
                long ttl = r.u32();
                int len = r.u16(), start = r.pos;
                r.need(len);
                if (cls == CLASS_IN) records.add(new Object[] {name, type, ttl, start, len});
                r.pos = start + len;
            }
            // Only a packet read through to its end counts, so a cut-off one cannot leave half its records.
            for (Object[] rec : records) {
                @SuppressWarnings("unchecked") List<String> name = (List<String>) rec[0];
                int type = (Integer) rec[1], start = (Integer) rec[3], len = (Integer) rec[4];
                long ttl = (Long) rec[2];
                long until = now + Math.min(ttl * 1000, LONGEST_MS);
                try {
                    take(name, type, ttl == 0, until, data, start, len, from, now);
                } catch (IllegalArgumentException ignored) {
                    // One malformed record is passed over; the rest of the packet still counts.
                }
            }
        }

        private void take(List<String> name, int type, boolean bye, long until, byte[] data, int start, int len, String from, long now) {
            Reader r = new Reader(data, start + len);
            r.pos = start;
            String key = key(name);
            if (type == TYPE_PTR) {
                if (name.size() < 3) return;
                List<String> target = r.name();
                // An instance of this domain is its first label in front of the domain's own.
                if (target.size() != name.size() + 1 || !key(target.subList(1, target.size())).equals(key)) return;
                Map<String, Ptr> m = ptrs.get(key);
                String instance = key(target);
                if (bye) {
                    if (m != null && m.remove(instance) != null) ptrCount--;
                    if (m != null && m.isEmpty()) ptrs.remove(key);
                    return;
                }
                if (m == null) {
                    if (ptrs.size() >= MOST && (!purge(now) || ptrs.size() >= MOST)) return;
                    ptrs.put(key, m = new HashMap<>());
                }
                if (!m.containsKey(instance)) {
                    if (ptrCount >= MOST && (!purge(now) || ptrCount >= MOST)) return;
                    ptrCount++;
                }
                m.put(instance, new Ptr(target.get(0), until));
                unanswered.remove(instance); // only the device itself sends its PTR, so it is back
            } else if (type == TYPE_SRV) {
                int priority = r.u16(), weight = r.u16();
                int port = r.u16();
                List<String> heard = r.name();
                String target = key(heard);
                if (bye) {
                    // A goodbye ends only the record it names, not one for a port taken since.
                    Srv old = srvs.get(key);
                    if (old != null && old.port == port && old.target.equals(target)) srvs.remove(key);
                } else if (room(srvs, key, now)) {
                    srvs.put(key, new Srv(target, port, from, until, priority, weight, heard));
                    unanswered.remove(key);
                }
            } else if (type == TYPE_TXT) {
                Map<String, String> txt = new LinkedHashMap<>();
                while (r.pos < start + len) {
                    int n = r.u8();
                    r.need(n);
                    String entry = new String(data, r.pos, n, StandardCharsets.UTF_8);
                    r.pos += n;
                    if (entry.isEmpty()) continue;
                    int eq = entry.indexOf('=');
                    String k = (eq < 0 ? entry : entry.substring(0, eq)).toLowerCase(Locale.ROOT);
                    // DNS-SD's rule: the first of a key counts, and a key without "=" has no value.
                    if (!txt.containsKey(k)) txt.put(k, eq < 0 ? "" : entry.substring(eq + 1));
                }
                if (bye) {
                    Txt old = txts.get(key);
                    if (old != null && old.txt.equals(txt)) txts.remove(key);
                } else if (room(txts, key, now)) {
                    txts.put(key, new Txt(txt, java.util.Arrays.copyOfRange(data, start, start + len), until));
                }
            } else if (type == TYPE_A && len == 4) {
                String a = (data[start] & 255) + "." + (data[start + 1] & 255) + "." + (data[start + 2] & 255) + "." + (data[start + 3] & 255);
                if (bye) {
                    A old = as.get(key);
                    if (old != null && old.address.equals(a)) as.remove(key);
                } else if (room(as, key, now)) {
                    as.put(key, new A(a, until));
                }
            }
        }

        private <V> boolean room(Map<String, V> m, String key, long now) {
            return m.containsKey(key) || m.size() < MOST || purge(now) && m.size() < MOST;
        }

        /** Drops every expired record; whether any went. Once a moment, so a packet of records costs one walk. */
        private boolean purge(long now) {
            if (now == purgedAt) return false;
            purgedAt = now;
            int before = ptrCount + srvs.size() + txts.size() + as.size();
            for (Iterator<Map<String, Ptr>> it = ptrs.values().iterator(); it.hasNext(); ) {
                Map<String, Ptr> m = it.next();
                int n = m.size();
                m.values().removeIf(p -> p.until <= now);
                ptrCount -= n - m.size();
                if (m.isEmpty()) it.remove();
            }
            srvs.values().removeIf(s -> s.until <= now);
            unanswered.keySet().removeIf(k -> srvs.containsKey(k) || !known(k));
            txts.values().removeIf(t -> t.until <= now);
            as.values().removeIf(a -> a.until <= now);
            return ptrCount + srvs.size() + txts.size() + as.size() < before;
        }

        /** Whether an instance's full name still has a PTR; its domain is all after its first label. */
        private boolean known(String full) {
            int cut = full.indexOf('\0');
            Map<String, Ptr> m = cut < 0 ? null : ptrs.get(full.substring(cut + 1));
            return m != null && m.containsKey(full);
        }

        private boolean gone(String full, Srv s, long now) {
            Long since = unanswered.get(full);
            return (s == null || s.until <= now) && since != null && now - since >= GONE_MS;
        }

        /** The instances of domain heard, those with a port and address resolved. */
        synchronized Look look(String domain, long now) {
            purge(now);
            Look out = new Look();
            Map<String, Ptr> m = ptrs.get(key(labels(domain)));
            if (m == null) return out;
            for (Map.Entry<String, Ptr> e : m.entrySet()) {
                Srv s = srvs.get(e.getKey());
                // A device gone without a goodbye leaves its PTR for an hour or more, but never answers for it.
                // It is still a doubt: one that only missed its answers would come back when asked again.
                if (gone(e.getKey(), s, now)) {
                    out.gone++;
                    continue;
                }
                out.found++;
                Txt t = txts.get(e.getKey());
                // Without its TXT, a stand-in cannot be told from the device it stands in for.
                if (s == null || t == null) continue;
                A a = as.get(s.target);
                if (a != null) out.complete++;
                // Without an address record, the device that sent the port is the one to reach.
                out.services.add(new Service(e.getValue().instance, a != null ? a.address : s.from, s.port, new LinkedHashMap<>(t.txt)));
            }
            return out;
        }

        /** An instance's records as one responder holds them, to be repeated exactly. */
        static final class Held {
            final int priority, weight, port;
            final List<String> target;
            final byte[] txt, address;

            Held(int priority, int weight, int port, List<String> target, byte[] txt, byte[] address) {
                this.priority = priority;
                this.weight = weight;
                this.port = port;
                this.target = target;
                this.txt = txt;
                this.address = address;
            }
        }

        /**
         * The SRV and TXT of the instance full (its labels), and its host's address, as heard from the
         * address from, all still current; null when any of the SRV or TXT is missing, stale or another's.
         */
        synchronized Held held(List<String> full, String from, long now) {
            String key = key(full);
            Srv s = srvs.get(key);
            Txt t = txts.get(key);
            if (s == null || t == null || s.until <= now || t.until <= now || !s.from.equals(from)) return null;
            A a = as.get(s.target);
            byte[] address = a == null || a.until <= now ? null : ipv4(a.address);
            return new Held(s.priority, s.weight, s.port, s.heard, t.raw, address);
        }

        /** The questions that would fill in what the instances of domain still lack, as {name, type}. */
        synchronized List<String[]> missing(String domain, long now) {
            List<String[]> out = new ArrayList<>();
            Map<String, Ptr> m = ptrs.get(key(labels(domain)));
            if (m == null) return out;
            for (Map.Entry<String, Ptr> e : m.entrySet()) {
                if (e.getValue().until <= now) continue;
                String full = e.getValue().instance + "." + domain;
                Srv s = srvs.get(e.getKey());
                if (gone(e.getKey(), s, now)) { // asked for its port alone, until it answers or its PTR runs out
                    out.add(new String[] {full, Integer.toString(TYPE_SRV)});
                    continue;
                }
                if (s == null || s.until <= now) {
                    if (!unanswered.containsKey(e.getKey()) && unanswered.size() < MOST) unanswered.put(e.getKey(), now);
                    out.add(new String[] {full, Integer.toString(TYPE_SRV)});
                }
                Txt t = txts.get(e.getKey());
                if (t == null || t.until <= now) out.add(new String[] {full, Integer.toString(TYPE_TXT)});
                if (s != null && s.until > now) {
                    A a = as.get(s.target);
                    if (a == null || a.until <= now) out.add(new String[] {s.target.replace('\0', '.'), Integer.toString(TYPE_A)});
                }
                if (out.size() > 64) break;
            }
            return out;
        }

        /**
         * A one-question query. A name whose first label holds a dot, as an instance name can, is passed
         * with the instance first: everything before the domain's last three labels is that one label.
         */
        static byte[] query(String name, int type) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(0); out.write(0); // id
            out.write(0); out.write(0); // a standard query
            out.write(0); out.write(1); // one question
            for (int i = 0; i < 6; i++) out.write(0);
            List<String> labels = labels(name);
            if (type != TYPE_PTR && type != TYPE_A && labels.size() > 4) {
                String instance = String.join(".", labels.subList(0, labels.size() - 3));
                List<String> rest = new ArrayList<>(labels.subList(labels.size() - 3, labels.size()));
                labels = new ArrayList<>();
                labels.add(instance);
                labels.addAll(rest);
            }
            for (String l : labels) {
                byte[] b = l.getBytes(StandardCharsets.UTF_8);
                out.write(Math.min(b.length, 63));
                out.write(b, 0, Math.min(b.length, 63));
            }
            out.write(0);
            out.write(type >> 8); out.write(type);
            out.write(0); out.write(CLASS_IN);
            return out.toByteArray();
        }

        static List<String> labels(String name) {
            List<String> out = new ArrayList<>();
            for (String l : name.split("\\.")) if (!l.isEmpty()) out.add(l);
            return out;
        }

        private static String key(List<String> labels) {
            return String.join("\0", labels).toLowerCase(Locale.ROOT);
        }
    }

    /** Reads a DNS packet, throwing IllegalArgumentException for anything that runs past its end. */
    static final class Reader {
        final byte[] data;
        final int end;
        int pos;

        Reader(byte[] data, int end) {
            this.data = data;
            this.end = Math.min(end, data.length);
        }

        void need(int n) {
            if (n < 0 || pos + n > end) throw new IllegalArgumentException("short packet");
        }

        void skip(int n) { need(n); pos += n; }
        int u8() { need(1); return data[pos++] & 255; }
        int u16() { return u8() << 8 | u8(); }
        long u32() { return (long) u16() << 16 | u16(); }

        /** A name, following compression pointers backward only, so a loop cannot hold the reader. */
        List<String> name() {
            List<String> out = new ArrayList<>();
            int at = pos, total = 0, limit = pos, hops = 0;
            boolean jumped = false;
            while (true) {
                if (at >= end) throw new IllegalArgumentException("short packet");
                int n = data[at] & 255;
                if (n == 0) {
                    if (!jumped) pos = at + 1;
                    return out;
                }
                if ((n & 0xc0) == 0xc0) {
                    if (at + 1 >= end) throw new IllegalArgumentException("short packet");
                    int to = (n & 0x3f) << 8 | data[at + 1] & 255;
                    // Backward only, so no loop; and few, so a chain of them costs little.
                    if (to >= limit || ++hops > 32) throw new IllegalArgumentException("bad name pointer");
                    if (!jumped) pos = at + 2;
                    jumped = true;
                    limit = to;
                    at = to;
                    continue;
                }
                if ((n & 0xc0) != 0) throw new IllegalArgumentException("bad label");
                if (at + 1 + n > end) throw new IllegalArgumentException("short packet");
                total += n + 1;
                if (total > 255) throw new IllegalArgumentException("name too long");
                out.add(new String(data, at + 1, n, StandardCharsets.UTF_8));
                at += 1 + n;
            }
        }
    }
}
