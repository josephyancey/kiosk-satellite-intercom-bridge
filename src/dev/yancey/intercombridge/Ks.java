package dev.yancey.intercombridge;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The Kiosk Satellite intercom, as Kiosk Phone (github.com/mpjanofsky/kiosk-phone,
 * docs/protocol.md) verified it against real kiosks. No Kiosk Satellite code is used.
 */
final class Ks {
    private Ks() {}

    /** One Kiosk Satellite audio frame: 80 ms of 16 kHz mono PCM16, little-endian. */
    static final int FRAME_BYTES = 2560;
    private static final long TOKEN_LIFE_MS = 60000;
    static final int REQUEST_MS = 4000;

    /** The first 8 hex digits of sha256(key): how two ends tell they share a key without showing it. */
    static String digest(String key) {
        return Crypto.hex(Crypto.sha256(key)).substring(0, 8);
    }

    /** Signs and checks call tokens with the fleet's intercom key. */
    static final class Auth {
        private final String key;
        private final Map<String, Long> seen = new HashMap<>(); // tokens used, by expiry, so none is replayed

        Auth(String key) { this.key = key; }

        String keyDigest() { return digest(key); }

        private String sign(String payload) {
            byte[] mac = Crypto.hmac(("intercom:" + key).getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().encodeToString(mac);
        }

        /** A one-use token for call, from the device with id from. */
        String token(String call, String from) {
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("exp", System.currentTimeMillis() + TOKEN_LIFE_MS);
            claims.put("from", from);
            claims.put("intercom", call);
            claims.put("n", Crypto.hex(Crypto.random(12)));
            String payload = Base64.getUrlEncoder().encodeToString(Json.write(claims).getBytes(StandardCharsets.UTF_8));
            return payload + "." + sign(payload);
        }

        /** Whether token was signed with the key, is for call, is unexpired and unused. One that passes is spent. */
        boolean verify(String token, String call) {
            int dot = token.indexOf('.');
            if (dot < 0) return false;
            String payload = token.substring(0, dot);
            if (!MessageDigest.isEqual(token.substring(dot + 1).getBytes(StandardCharsets.UTF_8), sign(payload).getBytes(StandardCharsets.UTF_8))) return false;
            Map<String, Object> claims;
            try {
                claims = Json.object(Base64.getUrlDecoder().decode(payload));
            } catch (IllegalArgumentException e) {
                return false;
            }
            long exp = Json.num(claims, "exp"), now = System.currentTimeMillis();
            if (!call.equals(Json.str(claims, "intercom")) || exp < now) return false;
            synchronized (seen) {
                for (Iterator<Long> it = seen.values().iterator(); it.hasNext(); ) if (it.next() < now) it.remove();
                if (seen.containsKey(token)) return false;
                seen.put(token, exp);
            }
            return true;
        }
    }

    /** How a device presents itself in a call ("from"). */
    static final class Peer {
        String id = "", name = "", address = "", version = "";
        int port;
        boolean tls;

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("name", name); m.put("address", address); m.put("port", port);
            m.put("version", version); m.put("tls", tls);
            return m;
        }

        static Peer from(Map<String, Object> m) {
            Peer p = new Peer();
            p.id = Json.str(m, "id"); p.name = Json.str(m, "name"); p.address = Json.str(m, "address");
            p.version = Json.str(m, "version"); p.port = (int) Json.num(m, "port"); p.tls = Json.bool(m, "tls");
            return p;
        }
    }

    /** What GET /api/intercom/identity answers. */
    static final class Identity {
        String id, name, key;
        boolean enabled, dnd, tls;
        int endpointPort;
    }

    /** Calls real kiosks. */
    static final class Client {
        private final Auth auth;
        private final Map<String, Object[]> cache = new HashMap<>(); // host:port to {Identity, Long at}

        Client(Auth auth) { this.auth = auth; }

        /** A kiosk's identity. Kiosks answer one request a second per client, so a copy younger than that is reused. */
        Identity identity(String host, int adminPort) throws IOException {
            String k = host + ":" + adminPort;
            synchronized (cache) {
                Object[] c = cache.get(k);
                if (c != null && System.currentTimeMillis() - (Long) c[1] < 1100) return (Identity) c[0];
            }
            Http.Response r = Http.request("GET", host, adminPort, "/api/intercom/identity", null, null, REQUEST_MS);
            if (r.status != 200) throw new IOException("identity: HTTP " + r.status);
            Map<String, Object> m = Json.object(r.body);
            Identity id = new Identity();
            id.id = Json.str(m, "id"); id.name = Json.str(m, "name"); id.key = Json.str(m, "key");
            id.enabled = Json.bool(m, "enabled"); id.dnd = Json.bool(m, "dnd");
            Map<String, Object> ep = Json.obj(m, "endpoint");
            id.endpointPort = (int) Json.num(ep, "port");
            id.tls = Json.bool(ep, "tls");
            synchronized (cache) {
                cache.put(k, new Object[] {id, System.currentTimeMillis()});
            }
            return id;
        }

        boolean keyMatches(Identity id) {
            return auth.keyDigest().equals(id.key);
        }

        private Http.Response post(String host, int port, String path, String call, String from, Object body) throws IOException {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("Content-Type", "application/json");
            h.put("Authorization", "Bearer " + auth.token(call, from));
            return Http.request("POST", host, port, path, h, Json.write(body).getBytes(StandardCharsets.UTF_8), REQUEST_MS);
        }

        /**
         * Rings a kiosk at its call endpoint. Returns its status word: ringing, auto, listening, busy,
         * dnd, off, refused, or key / tls when the kiosk refused us.
         */
        String call(String host, int endpointPort, String call, String kind, Peer from) throws IOException {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("call", call);
            body.put("kind", kind);
            body.put("from", from.toMap());
            Http.Response r = post(host, endpointPort, "/api/intercom/call", call, from.id, body);
            if (r.status == 403) return "key";
            if (r.status == 409 || r.status == 426) return "tls";
            if (r.status != 200) throw new IOException("call: HTTP " + r.status);
            String status = Json.str(Json.object(r.body), "status");
            if (status.isEmpty()) throw new IOException("call: no status");
            return status;
        }

        /** Tells a kiosk what happened to a call: answer, decline, missed, cancel or hangup. */
        void signal(String host, int endpointPort, String call, String from, String action) throws IOException {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("action", action);
            Http.Response r = post(host, endpointPort, "/api/intercom/call/" + Http.escape(call), call, from, body);
            if (r.status != 200) throw new IOException(action + ": HTTP " + r.status);
        }

        /** Opens a call's audio socket on a kiosk. The caller opens it, once the call is answered. */
        WebSocket dialAudio(String host, int endpointPort, String call, String from) throws IOException {
            return WebSocket.dial(host, endpointPort, "/api/intercom/audio/" + Http.escape(call) + "?token="
                    + Http.escape(auth.token(call, from)), REQUEST_MS);
        }
    }

    /** What a stand-in kiosk passes on to the bridge. Methods run on the request's thread. */
    interface Calls {
        /** A kiosk calling this stand-in. Returns the status word it is told. */
        String ring(String call, String kind, Peer from, String remote);
        /** A kiosk's word on a call. False when the call is not one the bridge knows. */
        boolean signal(String call, String action);
        boolean hasCall(String call);
        /** A call's audio socket, opened by the kiosk. The bridge owns and closes it. */
        void audio(String call, WebSocket ws);
    }

    /** Serves a stand-in kiosk's intercom routes. */
    static Http.Handler standin(String id, String name, String version, int[] port, Auth auth, Calls calls) {
        return r -> {
            String p = r.path;
            if (r.method.equals("GET") && p.equals("/api/intercom/identity")) {
                Map<String, Object> ep = new LinkedHashMap<>();
                ep.put("port", port[0]);
                ep.put("tls", false);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", id); m.put("name", name); m.put("version", version); m.put("enabled", true);
                m.put("key", auth.keyDigest()); m.put("dnd", false); m.put("endpoint", ep);
                r.json(200, m);
            } else if (r.method.equals("POST") && p.equals("/api/intercom/call")) {
                Map<String, Object> req = Json.object(r.body);
                String call = Json.str(req, "call");
                Peer from = Peer.from(Json.obj(req, "from"));
                Map<String, Object> out = new LinkedHashMap<>();
                if (call.isEmpty() || from.id.isEmpty()) {
                    out.put("error", "call and from required");
                    r.json(400, out);
                } else if (!auth.verify(bearer(r), call)) {
                    out.put("status", "key");
                    r.json(403, out);
                } else if (from.tls) {
                    out.put("status", "tls");
                    r.json(409, out);
                } else {
                    out.put("status", calls.ring(call, Json.str(req, "kind"), from, r.remoteHost()));
                    r.json(200, out);
                }
            } else if (r.method.equals("POST") && p.startsWith("/api/intercom/call/")) {
                String call = Http.unescape(p.substring("/api/intercom/call/".length()));
                String action = Json.str(Json.object(r.body), "action");
                if (!auth.verify(bearer(r), call)) {
                    r.json(403, new LinkedHashMap<String, Object>());
                } else if (action.isEmpty()) {
                    r.json(400, new LinkedHashMap<String, Object>());
                } else if (!calls.signal(call, action)) {
                    r.json(404, new LinkedHashMap<String, Object>());
                } else {
                    Map<String, Object> ok = new LinkedHashMap<>();
                    ok.put("ok", true);
                    r.json(200, ok);
                }
            } else if (r.method.equals("GET") && p.startsWith("/api/intercom/audio/")) {
                String call = Http.unescape(p.substring("/api/intercom/audio/".length()));
                if (!auth.verify(r.param("token"), call)) {
                    r.json(403, new LinkedHashMap<String, Object>());
                } else if (!calls.hasCall(call)) {
                    r.json(404, new LinkedHashMap<String, Object>());
                } else {
                    WebSocket ws = WebSocket.upgrade(r);
                    if (ws != null) calls.audio(call, ws);
                }
            } else {
                r.json(404, new LinkedHashMap<String, Object>());
            }
        };
    }

    private static String bearer(Http.Request r) {
        String v = r.header("authorization");
        return v.startsWith("Bearer ") ? v.substring(7) : v;
    }
}
