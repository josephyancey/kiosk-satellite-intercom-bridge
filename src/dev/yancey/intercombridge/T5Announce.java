package dev.yancey.intercombridge;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TECHO5 announcements, following echod/internal/feature/announce: a POST to /announce whose body
 * is the voice as 16 kHz mono PCM16, with who sent it and what was said in headers, signed with an
 * HMAC keyed from the house word.
 */
final class T5Announce {
    static final String PATH = "/announce";
    private static final String FROM = "X-Techo5-From", TEXT = "X-Techo5-Text", KIND = "X-Techo5-Kind", ID = "X-Techo5-Id",
            AUTH = "X-Techo5-Auth", TIME = "X-Techo5-Time", LEGACY = "X-Techo5-House";
    private static final String AUDIO_TYPE = "audio/L16; rate=16000; channels=1";
    private static final String AUTH_LABEL = "techo5-announce hmac";

    /** The longest voice a device takes: twenty seconds. */
    static final int MAX_BYTES = 20 * 16000 * 2;
    private static final long SKEW_MS = 5 * 60 * 1000;
    private static final int NONCES_KEPT = 4096, SEND_MS = 4000;

    /** One announcement. Voice is 16 kHz mono PCM16; empty for one of words only. */
    static final class Message {
        String from = "", text = "", kind = "", id = "";
        byte[] voice = new byte[0];
    }

    private final String word;
    private final Map<String, Long> nonces = new HashMap<>();
    private final Map<String, Long> offsets = new HashMap<>(); // how far each device's clock is from ours

    T5Announce(String houseWord) {
        this.word = houseWord;
    }

    private byte[] key() {
        return Crypto.sha256(AUTH_LABEL + ":" + word);
    }

    /** What the signature covers, one field a line. */
    private static byte[] signed(String ts, String nonce, String method, String path, Map<String, String> h, byte[] body) {
        StringBuilder b = new StringBuilder();
        for (String part : new String[] {"v1", ts, nonce, method, path, get(h, FROM), get(h, TEXT), get(h, KIND), get(h, ID),
                Crypto.hex(Crypto.sha256(body))}) {
            b.append(part).append('\n');
        }
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String get(Map<String, String> h, String k) {
        for (Map.Entry<String, String> e : h.entrySet()) if (e.getKey().equalsIgnoreCase(k)) return e.getValue();
        return "";
    }

    private String sign(String method, String path, Map<String, String> headers, byte[] body, long atMs) {
        String ts = Long.toString(Math.floorDiv(atMs, 1000L)), nonce = Crypto.hex(Crypto.random(12));
        return "v1 " + ts + " " + nonce + " " + Crypto.hex(Crypto.hmac(key(), signed(ts, nonce, method, path, headers, body)));
    }

    private synchronized boolean fresh(String nonce, long now) {
        if (nonces.containsKey(nonce)) return false;
        if (nonces.size() >= NONCES_KEPT) {
            for (Iterator<Long> it = nonces.values().iterator(); it.hasNext(); ) if (now - it.next() > 2 * SKEW_MS) it.remove();
            if (nonces.size() >= NONCES_KEPT) return false;
        }
        nonces.put(nonce, now);
        return true;
    }

    /**
     * Reads and checks an announcement sent to us, and answers as a device would: 204 when taken, 409
     * with our clock when the sender's is out, 403 when not signed by this house. Null when refused.
     */
    Message receive(Http.Request r) throws IOException {
        if (!r.method.equals("POST")) {
            r.text(405, "post an announcement");
            return null;
        }
        byte[] body = r.body.length > MAX_BYTES ? Arrays.copyOf(r.body, MAX_BYTES) : r.body;
        long now = System.currentTimeMillis();
        int verdict = verify(r, body, now);
        if (verdict == 409) {
            Map<String, String> h = new LinkedHashMap<>();
            h.put(TIME, Long.toString(now / 1000));
            h.put("Content-Type", "text/plain; charset=utf-8");
            r.respond(409, h, "our clocks disagree\n".getBytes(StandardCharsets.UTF_8));
            return null;
        }
        if (verdict != 0) {
            r.text(403, "not this house");
            return null;
        }
        if (body.length % 2 != 0) body = Arrays.copyOf(body, body.length - 1);
        Message m = new Message();
        m.from = Http.unescape(r.header(FROM));
        m.text = Http.unescape(r.header(TEXT));
        m.kind = Http.unescape(r.header(KIND));
        m.id = Http.unescape(r.header(ID));
        m.voice = body;
        if (m.kind.isEmpty() && m.text.isEmpty() && m.voice.length == 0) {
            r.text(400, "an announcement says something");
            return null;
        }
        r.respond(204, null, new byte[0]);
        return m;
    }

    /** 0 when signed by this house, 409 when signed at a time too far from our clock, else 403. */
    private int verify(Http.Request r, byte[] body, long now) {
        if (word.isEmpty()) return 403;
        String auth = r.header(AUTH);
        if (auth.isEmpty()) {
            String old = r.header(LEGACY);
            return !old.isEmpty() && MessageDigest.isEqual(old.getBytes(StandardCharsets.UTF_8), word.getBytes(StandardCharsets.UTF_8)) ? 0 : 403;
        }
        String[] parts = auth.trim().split("\\s+");
        if (parts.length != 4 || !parts[0].equals("v1")) return 403;
        long sec;
        try {
            sec = Long.parseLong(parts[1]);
        } catch (NumberFormatException e) {
            return 403;
        }
        Map<String, String> h = new LinkedHashMap<>(r.headers);
        byte[] want = Crypto.hmac(key(), signed(parts[1], parts[2], r.method, r.path, h, body));
        byte[] got = Crypto.unhex(parts[3]);
        if (got == null || !MessageDigest.isEqual(got, want)) return 403;
        long d = now - sec * 1000;
        if (d > SKEW_MS || d < -SKEW_MS) return 409;
        return fresh(parts[2], now) ? 0 : 403;
    }

    /**
     * Delivers an announcement to a device. When the device says our clock is out, it is signed
     * again by the device's clock, as devices do with each other.
     */
    void send(String address, int port, Message m) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(FROM, Http.escape(m.from));
        headers.put(TEXT, Http.escape(m.text));
        headers.put("Content-Type", AUDIO_TYPE);
        if (!m.kind.isEmpty()) {
            headers.put(KIND, Http.escape(m.kind));
            headers.put(ID, Http.escape(m.id));
        }
        String addr = Http.hostPort(address, port);
        for (int attempt = 0; ; attempt++) {
            long off;
            synchronized (this) {
                Long o = offsets.get(addr);
                off = o == null ? 0 : o;
            }
            Map<String, String> h = new LinkedHashMap<>(headers);
            h.put(AUTH, sign("POST", PATH, headers, m.voice, System.currentTimeMillis() + off));
            Http.Response r = Http.request("POST", address, port, PATH, h, m.voice, SEND_MS);
            if (r.status == 409 && attempt == 0) {
                try {
                    long theirs = Long.parseLong(r.header(TIME)) * 1000, d = theirs - System.currentTimeMillis();
                    d = Math.min(d, 24L * 3600 * 1000); // never sign far into the future on someone else's word
                    synchronized (this) {
                        offsets.put(addr, d);
                    }
                    continue;
                } catch (NumberFormatException ignored) {
                }
            }
            if (r.status == 403) throw new IOException("the device refused it: its house word is different");
            if (r.status >= 300) throw new IOException("the device said HTTP " + r.status);
            return;
        }
    }
}
