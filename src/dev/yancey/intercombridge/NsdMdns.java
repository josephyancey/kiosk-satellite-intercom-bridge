package dev.yancey.intercombridge;

import android.content.Context;
import android.content.res.Configuration;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Build;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * {@link Mdns} through Android's NsdManager, which shares the system's mDNS responder with every app.
 *
 * The bridge keeps its own NsdManager clients rather than the app's. Before Android 14 each client may
 * have ten requests going and one resolve at a time, and a resolve that never hears back holds that
 * one resolve for good, with no way to cancel it. On the app's own client that would stop Kiosk
 * Satellite's lookups along with the bridge's. So lookups go through one client, replaced when it is
 * stuck, and advertisements through others, a few to each. {@link #close} lets them all go.
 */
final class NsdMdns implements Mdns {
    private static final int RESOLVE_MS = 3000;
    private static final int START_MS = 1000; // how long a browse has to say it started or failed
    private static final int RETRIES = 3; // tries again after Android's request limit turns one away
    private static final int ADS_PER_CLIENT = 8; // under the ten requests a client may have going
    private static final long RENEW_MS = 30000; // the soonest a stuck lookup client is replaced again
    private static final int LEAKS = 48; // stuck clients left behind, unable to disconnect, before replacing stops
    private static final long UNANSWERED_MS = 5 * 60000; // how long a service that never answered a resolve is left alone

    private final Context context;
    private final Object resolving = new Object(); // one resolve at a time per client
    private final Map<String, String> looks = new ConcurrentHashMap<>(); // type to how its last look went
    private final Map<String, Boolean> complete = new ConcurrentHashMap<>(); // type to whether every one found resolved
    private final Map<String, Long> unanswered = new ConcurrentHashMap<>(); // "type/name" to when to try it again
    private final List<AdClient> adClients = new ArrayList<>();
    private NsdManager look;
    private long lookSince;
    private int leaks;
    private boolean closed;

    private static final class AdClient {
        final NsdManager nsd;
        int ads;
        AdClient(NsdManager nsd) { this.nsd = nsd; }
    }

    NsdMdns(Context context) {
        this.context = context;
    }

    /**
     * A new NsdManager client: each context made here gets its own, with its own request limit. Failing
     * that, the app's own, which is shared with Kiosk Satellite and so is never disconnected.
     */
    private NsdManager newClient() {
        try {
            Context c = context.createConfigurationContext(new Configuration(context.getResources().getConfiguration()));
            NsdManager m = (NsdManager) c.getSystemService(Context.NSD_SERVICE);
            if (m != null) return m;
        } catch (RuntimeException ignored) {
        }
        return shared();
    }

    private NsdManager shared() {
        return (NsdManager) context.getSystemService(Context.NSD_SERVICE);
    }

    /** Lets every client of the bridge's go, once its advertisements are closed. */
    synchronized void close() {
        closed = true;
        if (look != null) disconnect(look);
        look = null;
        for (AdClient c : adClients) disconnect(c.nsd);
        adClients.clear();
    }

    private synchronized NsdManager lookClient() throws IOException {
        if (closed) throw new IOException("mDNS is closed");
        if (look == null) {
            look = newClient();
            lookSince = System.currentTimeMillis();
        }
        return look;
    }

    /**
     * Swaps the lookup client for a new one, at most once per RENEW_MS. The old one is disconnected,
     * which ends its stuck resolve, where Android lets an app do that; where it doesn't, the old client
     * keeps a thread, so only LEAKS such are left behind before this stops. True if it swapped.
     */
    private synchronized boolean renewLook() {
        if (closed || leaks >= LEAKS || look != null && System.currentTimeMillis() - lookSince < RENEW_MS) return false;
        if (look != null && !disconnect(look)) leaks++;
        look = newClient();
        lookSince = System.currentTimeMillis();
        return true;
    }

    /**
     * NsdManager.disconnect(), hidden, where Android has it and lets an app call it: drops the client and
     * its requests. Never the app's own client.
     */
    private boolean disconnect(NsdManager m) {
        if (m == shared()) return true; // nothing of ours to let go, and not ours to close
        try {
            m.getClass().getMethod("disconnect").invoke(m);
            return true;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return false;
        }
    }

    @Override
    public boolean lastLookComplete(String type) {
        return complete.getOrDefault(type, false);
    }

    @Override
    public synchronized Map<String, Object> diagnostics() {
        Map<String, Object> d = new LinkedHashMap<>(looks);
        if (look != null && look == shared()) d.put("client", "the app's own; its own clients were not available");
        if (leaks > 0) d.put("stuck_clients_left", leaks);
        return d;
    }

    @Override
    public List<Service> browse(String type, long lookMs) throws IOException, InterruptedException {
        NsdManager nsd = lookClient();
        List<NsdServiceInfo> found = new ArrayList<>();
        // A browse turned away by the request limit waits and tries again.
        for (int attempt = 0; ; attempt++) {
            AtomicInteger failed = new AtomicInteger();
            CountDownLatch started = new CountDownLatch(1);
            NsdManager.DiscoveryListener l = new NsdManager.DiscoveryListener() {
                @Override public void onStartDiscoveryFailed(String t, int code) { failed.set(code == 0 ? -1 : code); started.countDown(); }
                @Override public void onStopDiscoveryFailed(String t, int code) {}
                @Override public void onDiscoveryStarted(String t) { started.countDown(); }
                @Override public void onDiscoveryStopped(String t) {}
                @Override public void onServiceFound(NsdServiceInfo info) { synchronized (found) { found.add(info); } }
                @Override public void onServiceLost(NsdServiceInfo info) {}
            };
            try {
                nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, l);
            } catch (RuntimeException e) {
                throw new IOException("mDNS browse for " + type + ": " + e.getMessage());
            }
            started.await(START_MS, TimeUnit.MILLISECONDS);
            if (failed.get() == NsdManager.FAILURE_MAX_LIMIT && attempt < RETRIES) {
                backOff(attempt);
                continue;
            }
            try {
                if (failed.get() == 0) Thread.sleep(lookMs);
            } finally {
                if (failed.get() == 0) {
                    try { nsd.stopServiceDiscovery(l); } catch (RuntimeException ignored) {}
                }
            }
            if (failed.get() != 0) {
                String why = "mDNS browse for " + type + " failed (" + failed.get() + ")";
                looks.put(type, why);
                complete.put(type, false);
                if (failed.get() == NsdManager.FAILURE_MAX_LIMIT && renewLook()) why += "; starting over with a new mDNS client";
                throw new IOException(why);
            }
            break;
        }
        List<NsdServiceInfo> seen;
        synchronized (found) {
            seen = new ArrayList<>(found);
        }
        List<Service> out = new ArrayList<>();
        List<String> names = new ArrayList<>();
        Map<Integer, Integer> failures = new LinkedHashMap<>();
        int skipped = 0, renewed = 0;
        long now = System.currentTimeMillis();
        unanswered.values().removeIf(until -> until < now);
        for (NsdServiceInfo info : seen) {
            if (names.contains(info.getServiceName())) continue;
            names.add(info.getServiceName());
            String key = type + "/" + info.getServiceName();
            // Never for the bridges: a running bridge skipped would look like none running.
            if (!type.equals(Runner.BRIDGE_SERVICE) && unanswered.containsKey(key)) {
                skipped++;
                continue;
            }
            int[] why = new int[1];
            NsdServiceInfo r = resolve(nsd, info, why);
            // Busy or at the limit means a resolve of ours never ended, and the client is stuck. Before
            // Android 14 an unanswered resolve can't be called off, so it leaves the client stuck too.
            // The rest go through a new client, this one included unless it went unanswered.
            boolean refused = r == null && (why[0] == NsdManager.FAILURE_ALREADY_ACTIVE || why[0] == NsdManager.FAILURE_MAX_LIMIT);
            if ((refused || r == null && why[0] == TIMED_OUT && Build.VERSION.SDK_INT < 34) && renewLook()) {
                renewed++;
                nsd = lookClient();
                if (refused) r = resolve(nsd, info, why);
            }
            if (r == null || r.getHost() == null) {
                int code = r == null ? why[0] : -2;
                failures.put(code, failures.containsKey(code) ? failures.get(code) + 1 : 1);
                // A device gone quiet, whose record mDNS still remembers, would only get stuck again.
                if (code == TIMED_OUT) unanswered.put(key, now + UNANSWERED_MS);
                continue;
            }
            Map<String, String> txt = new LinkedHashMap<>();
            Map<String, byte[]> attrs = r.getAttributes();
            if (attrs != null) for (Map.Entry<String, byte[]> e : attrs.entrySet()) {
                txt.put(e.getKey(), e.getValue() == null ? "" : new String(e.getValue(), StandardCharsets.UTF_8));
            }
            InetAddress a = r.getHost();
            out.add(new Service(r.getServiceName(), a.getHostAddress(), r.getPort(), txt));
        }
        StringBuilder note = new StringBuilder(names.size() + " found, " + out.size() + " resolved");
        for (Map.Entry<Integer, Integer> f : failures.entrySet()) {
            note.append(", ").append(f.getValue()).append(' ').append(failure(f.getKey()));
        }
        if (skipped > 0) note.append(", ").append(skipped).append(" skipped for not answering lately");
        if (renewed > 0) note.append("; mDNS client replaced ").append(renewed).append(renewed == 1 ? " time" : " times");
        looks.put(type, note.toString());
        complete.put(type, out.size() == names.size());
        return out;
    }

    private static final int TIMED_OUT = -3;

    private static String failure(int code) {
        switch (code) {
            case NsdManager.FAILURE_ALREADY_ACTIVE: return "refused as busy";
            case NsdManager.FAILURE_MAX_LIMIT: return "refused at the request limit";
            case TIMED_OUT: return "unanswered";
            case -2: return "without an address";
            default: return "failed (" + code + ")";
        }
    }

    private NsdServiceInfo resolve(NsdManager nsd, NsdServiceInfo info, int[] why) throws InterruptedException {
        synchronized (resolving) {
            int full = 0;
            for (int attempt = 0; attempt < 5; attempt++) {
                CountDownLatch done = new CountDownLatch(1);
                AtomicReference<NsdServiceInfo> got = new AtomicReference<>();
                AtomicInteger code = new AtomicInteger();
                NsdManager.ResolveListener l = new NsdManager.ResolveListener() {
                    @Override public void onResolveFailed(NsdServiceInfo i, int c) { code.set(c); done.countDown(); }
                    @Override public void onServiceResolved(NsdServiceInfo i) { got.set(i); done.countDown(); }
                };
                try {
                    nsd.resolveService(info, l);
                } catch (RuntimeException e) {
                    why[0] = -1;
                    return null;
                }
                if (!done.await(RESOLVE_MS, TimeUnit.MILLISECONDS)) {
                    // Android 14 can call it off; older ones keep it going, and the client stays busy.
                    if (Build.VERSION.SDK_INT >= 34) {
                        try { nsd.stopServiceResolution(l); } catch (RuntimeException ignored) {}
                    }
                    why[0] = TIMED_OUT;
                    return null;
                }
                if (got.get() != null) return got.get();
                why[0] = code.get();
                if (code.get() == NsdManager.FAILURE_ALREADY_ACTIVE) {
                    Thread.sleep(200); // a resolve of ours is still going
                } else if (code.get() == NsdManager.FAILURE_MAX_LIMIT && full < RETRIES) {
                    backOff(full++);
                } else {
                    return null;
                }
            }
            return null;
        }
    }

    /** Waits about 1, 2, then 4 seconds, staggered so other lookups get a turn. */
    private static void backOff(int attempt) throws InterruptedException {
        long ms = 1000L << attempt;
        Thread.sleep(ms + (long) (Math.random() * ms / 2));
    }

    @Override
    public Closeable advertise(String instance, String type, int port, Map<String, String> txt) throws IOException {
        NsdServiceInfo info = new NsdServiceInfo();
        try {
            info.setServiceName(instance);
            info.setServiceType(type);
            info.setPort(port);
            // A name heard from the network can be too long or not UTF-8, and Android throws for that.
            for (Map.Entry<String, String> e : txt.entrySet()) info.setAttribute(e.getKey(), e.getValue());
        } catch (RuntimeException e) {
            throw new IOException("mDNS advertising " + instance + ": " + e.getMessage());
        }
        AdClient client = adClient();
        CountDownLatch done = new CountDownLatch(1);
        AtomicInteger failed = new AtomicInteger();
        NsdManager.RegistrationListener l = new NsdManager.RegistrationListener() {
            @Override public void onRegistrationFailed(NsdServiceInfo i, int c) { failed.set(c == 0 ? -1 : c); done.countDown(); }
            @Override public void onUnregistrationFailed(NsdServiceInfo i, int c) {}
            @Override public void onServiceRegistered(NsdServiceInfo i) { done.countDown(); }
            @Override public void onServiceUnregistered(NsdServiceInfo i) {}
        };
        try {
            client.nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, l);
        } catch (RuntimeException e) {
            release(client);
            throw new IOException("mDNS advertising " + instance + ": " + e.getMessage());
        }
        try {
            done.await(RESOLVE_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (failed.get() != 0) {
            release(client);
            throw new IOException("mDNS advertising " + instance + " failed (" + failed.get() + ")");
        }
        boolean[] gone = new boolean[1];
        return () -> {
            synchronized (gone) {
                if (gone[0]) return;
                gone[0] = true;
            }
            try { client.nsd.unregisterService(l); } catch (RuntimeException ignored) {}
            release(client);
        };
    }

    /** A client with room for one more advertisement, which it counts as taken. */
    private synchronized AdClient adClient() throws IOException {
        if (closed) throw new IOException("mDNS is closed");
        for (AdClient c : adClients) {
            if (c.ads < ADS_PER_CLIENT) {
                c.ads++;
                return c;
            }
        }
        AdClient c = new AdClient(newClient());
        c.ads = 1;
        adClients.add(c);
        return c;
    }

    private synchronized void release(AdClient c) {
        c.ads--;
    }
}
