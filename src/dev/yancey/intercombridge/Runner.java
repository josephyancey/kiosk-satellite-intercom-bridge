package dev.yancey.intercombridge;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 * Runs a bridge only while no other bridge runs on the network. A running bridge advertises
 * _intercom-bridge._tcp with its id and since when it has run; the port is its status page, which
 * says whether it is running. A bridge that finds another one alive stands by, and looks again each
 * round; when two run at once, the one that started first stays and the other stands down.
 *
 * Only a bridge with the same intercom key counts: the one asking sends a nonce, and the status
 * page answers with an HMAC of its id, whether it runs, since and that nonce, keyed from the intercom
 * key. So a host that only claims to be a bridge cannot make the others stand down.
 */
final class Runner {
    static final String BRIDGE_SERVICE = "_intercom-bridge._tcp";

    /** What the runner reports as it goes. */
    interface Listener {
        void state(String level, String text);
    }

    static final class Other {
        final String id, address;
        final long since;
        Other(String id, String address, long since) { this.id = id; this.address = address; this.since = since; }
    }

    private final Bridge.Config cfg;
    private final Mdns mdns;
    private final ExecutorService pool;
    private final Bridge.Log log;
    private final Listener listener;
    private final String id;
    private final int statusPort;
    private final long everyMs;

    private Http.Server status;
    private volatile Bridge bridge;
    private Closeable adv;
    private volatile long since;
    private volatile boolean stopped;
    private String standingBy = "";
    private static final int DOUBTFUL_ROUNDS = 10; // about five minutes of rounds
    private int clearRounds; // rounds in a row that clearly found no running bridge, while standing by
    private int quietRounds; // rounds in a row that found no running bridge, in doubt or not

    Runner(Bridge.Config cfg, Mdns mdns, ExecutorService pool, Bridge.Log log, Listener listener, String id, int statusPort, long everyMs) {
        this.cfg = cfg;
        this.mdns = mdns;
        this.pool = pool;
        this.log = log;
        this.listener = listener;
        this.id = id;
        this.statusPort = statusPort;
        this.everyMs = everyMs;
    }

    boolean active() {
        return bridge != null;
    }

    Bridge bridge() {
        return bridge;
    }

    /** Runs rounds until {@link #stop}. */
    void run() {
        try {
            status = new Http.Server(cfg.listen, statusPort, this::serveStatus, pool, 1024); // GET only
        } catch (IOException e) {
            listener.state("off", "Status port " + statusPort + " is taken: " + e.getMessage());
            log.warn("The status port " + statusPort + " is taken; other bridges cannot see this one, so it stays off");
            return;
        }
        try {
            while (!stopped) {
                try {
                    round();
                } catch (RuntimeException | StackOverflowError e) {
                    log.warn("A round went wrong and the next one starts over: " + e);
                }
                if (stopped) break;
                Thread.sleep(everyMs);
            }
        } catch (InterruptedException ignored) {
        } finally {
            standDown();
            status.close();
        }
    }

    /** Takes the bridge down now; the round in progress, if any, ends on its own. */
    void stop() {
        stopped = true;
        standDown();
        Http.Server s = status;
        if (s != null) s.close();
    }

    /**
     * One round: look for other bridges, decide, and, while running, look for devices. A standby takes
     * over after two rounds in a row clearly found no bridge running. A look that failed, left a bridge
     * unresolved or could not reach one's status page is in doubt, since one missed answer must not
     * start a second bridge beside the running one; only DOUBTFUL_ROUNDS of those in a row, with no
     * bridge seen running, let it take over anyway, for a running bridge that went without a goodbye.
     */
    void round() throws InterruptedException {
        Look look = others();
        List<Other> others = look.running;
        if (bridge == null) {
            if (!others.isEmpty()) {
                clearRounds = quietRounds = 0;
            } else {
                clearRounds = look.doubtful ? 0 : clearRounds + 1;
                quietRounds++;
                if (clearRounds < 2 && quietRounds < DOUBTFUL_ROUNDS) return;
                if (clearRounds < 2) log.info("No bridge has answered as running for " + quietRounds + " rounds; this one takes over");
                clearRounds = quietRounds = 0;
                standUp();
            }
            if (!others.isEmpty()) {
                Other o = others.get(0);
                if (!o.address.equals(standingBy)) log.info("Another bridge runs at " + o.address + "; this one stands by");
                standingBy = o.address;
                listener.state("", "Standing by: the bridge at " + o.address + " is running");
                return;
            }
        } else {
            for (Other o : others) {
                if (o.since < since || o.since == since && o.id.compareTo(id) < 0) {
                    log.info("The bridge at " + o.address + " was running first; this one stands down");
                    standDown();
                    standingBy = o.address;
                    listener.state("", "Standing by: the bridge at " + o.address + " is running");
                    return;
                }
            }
        }
        Bridge b = bridge;
        if (b == null) return;
        b.scan();
        String err = b.lastError();
        listener.state(err.isEmpty() ? "on" : "warn", b.kioskCount() + " kiosks, " + b.echoCount() + " Echos"
                + (b.callCount() > 0 ? ", " + b.callCount() + " in a call" : "") + (err.isEmpty() ? "" : ". Last problem: " + err));
    }

    /** What one look for other bridges found. */
    static final class Look {
        final List<Other> running = new ArrayList<>();
        boolean doubtful; // the look failed, or a bridge it found could not be resolved or reached
    }

    /** The other bridges that answer that they are running, and whether the look was in doubt. */
    private Look others() throws InterruptedException {
        Look out = new Look();
        List<Mdns.Service> found;
        try {
            found = mdns.browse(BRIDGE_SERVICE, cfg.browseForMs);
        } catch (IOException e) {
            log.warn("Looking for other bridges: " + e.getMessage());
            out.doubtful = true;
            return out;
        }
        out.doubtful = !mdns.lastLookComplete(BRIDGE_SERVICE);
        for (Mdns.Service s : found) {
            if (s.txt("id").equals(id) || s.txt("id").isEmpty()) continue;
            // mDNS can remember a bridge that has gone; its status page is the word that it still runs.
            try {
                String nonce = Crypto.hex(Crypto.random(16));
                Http.Response r = Http.request("GET", s.address, s.port, "/status?nonce=" + nonce, null, null, Ks.REQUEST_MS);
                Map<String, Object> m = Json.object(r.body);
                String otherId = Json.str(m, "id");
                long otherSince = Json.num(m, "since");
                byte[] got = Crypto.unhex(Json.str(m, "proof"));
                if (r.status == 200 && Json.bool(m, "active") && otherId.equals(s.txt("id"))
                        && got != null && MessageDigest.isEqual(got, proof(otherId, true, otherSince, nonce))) {
                    out.running.add(new Other(otherId, s.address, otherSince));
                }
            } catch (IOException e) {
                out.doubtful = true; // gone, or only slow to answer
            }
        }
        return out;
    }

    private synchronized void standUp() {
        if (stopped) return;
        since = System.currentTimeMillis();
        Bridge b = new Bridge(cfg, mdns, pool, log);
        if (!cfg.noAdvertise) {
            Map<String, String> txt = new LinkedHashMap<>();
            txt.put("id", id);
            txt.put("since", Long.toString(since));
            txt.put("version", cfg.version);
            try {
                adv = mdns.advertise("intercom-bridge-" + id, BRIDGE_SERVICE, statusPort, txt);
            } catch (IOException e) {
                log.warn("Advertising the bridge: " + e.getMessage());
            }
        }
        bridge = b;
        standingBy = "";
        log.info("No other bridge is running; this one is");
        listener.state("on", "Running");
    }

    private synchronized void standDown() {
        Bridge b = bridge;
        bridge = null;
        Bridge.closeQuietly(adv);
        adv = null;
        if (b != null) b.close();
    }

    private void serveStatus(Http.Request r) throws IOException {
        if (!r.path.equals("/status") && !r.path.equals("/")) {
            r.text(404, "not found");
            return;
        }
        Bridge b = bridge;
        long at = b != null ? since : 0;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("active", b != null);
        m.put("since", at);
        String nonce = r.param("nonce");
        if (!nonce.isEmpty() && nonce.length() <= 64) m.put("proof", Crypto.hex(proof(id, b != null, at, nonce)));
        if (b != null) m.putAll(b.status());
        else m.put("version", cfg.version);
        Map<String, Object> looks = mdns.diagnostics();
        if (!looks.isEmpty()) m.put("mdns", looks);
        r.json(200, m);
    }

    /**
     * What a bridge with this intercom key answers to nonce: an HMAC of its id, whether it runs, since
     * and the nonce. Whether it runs is covered too, so a standby's answer can't be passed off as a running one's.
     */
    private byte[] proof(String bridgeId, boolean active, long at, String nonce) {
        byte[] key = Crypto.sha256("intercom-bridge status:" + cfg.intercomKey);
        return Crypto.hmac(key, (bridgeId + "\n" + (active ? "running" : "standing by") + "\n" + at + "\n" + nonce)
                .getBytes(StandardCharsets.UTF_8));
    }
}
