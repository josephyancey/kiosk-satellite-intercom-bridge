package dev.yancey.intercombridge;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** {@link Mdns} through Android's NsdManager, which shares the system's mDNS responder with every app. */
final class NsdMdns implements Mdns {
    private static final int RESOLVE_MS = 3000;
    private static final int START_MS = 1000; // how long a browse has to say it started or failed
    private static final int RETRIES = 3; // tries again after Android's per-app limit turns one away
    private final NsdManager nsd;
    private final Object resolving = new Object(); // older Androids resolve one service at a time

    NsdMdns(Context context) {
        nsd = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
    }

    @Override
    public List<Service> browse(String type, long lookMs) throws IOException, InterruptedException {
        List<NsdServiceInfo> found = new ArrayList<>();
        // Android caps how many browses and resolves an app has going, and this plugin shares the
        // cap with Kiosk Satellite's own, so a browse turned away for that waits and tries again.
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
                    try { nsd.stopServiceDiscovery(l); } catch (IllegalArgumentException ignored) {}
                }
            }
            if (failed.get() != 0) throw new IOException("mDNS browse for " + type + " failed (" + failed.get() + ")");
            break;
        }
        List<NsdServiceInfo> seen;
        synchronized (found) {
            seen = new ArrayList<>(found);
        }
        List<Service> out = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (NsdServiceInfo info : seen) {
            if (names.contains(info.getServiceName())) continue;
            names.add(info.getServiceName());
            NsdServiceInfo r = resolve(info);
            if (r == null || r.getHost() == null) continue;
            Map<String, String> txt = new LinkedHashMap<>();
            Map<String, byte[]> attrs = r.getAttributes();
            if (attrs != null) for (Map.Entry<String, byte[]> e : attrs.entrySet()) {
                txt.put(e.getKey(), e.getValue() == null ? "" : new String(e.getValue(), StandardCharsets.UTF_8));
            }
            InetAddress a = r.getHost();
            out.add(new Service(r.getServiceName(), a.getHostAddress(), r.getPort(), txt));
        }
        return out;
    }

    private NsdServiceInfo resolve(NsdServiceInfo info) throws InterruptedException {
        synchronized (resolving) {
            int full = 0;
            for (int attempt = 0; attempt < 5; attempt++) {
                CountDownLatch done = new CountDownLatch(1);
                AtomicReference<NsdServiceInfo> got = new AtomicReference<>();
                AtomicInteger code = new AtomicInteger();
                try {
                    nsd.resolveService(info, new NsdManager.ResolveListener() {
                        @Override public void onResolveFailed(NsdServiceInfo i, int c) { code.set(c); done.countDown(); }
                        @Override public void onServiceResolved(NsdServiceInfo i) { got.set(i); done.countDown(); }
                    });
                } catch (RuntimeException e) {
                    return null;
                }
                if (!done.await(RESOLVE_MS, TimeUnit.MILLISECONDS)) return null;
                if (got.get() != null) return got.get();
                if (code.get() == NsdManager.FAILURE_ALREADY_ACTIVE) {
                    Thread.sleep(200); // someone else in this app is resolving
                } else if (code.get() == NsdManager.FAILURE_MAX_LIMIT && full < RETRIES) {
                    backOff(full++);
                } else {
                    return null;
                }
            }
            return null;
        }
    }

    /** Waits about 1, 2, then 4 seconds, staggered so the kiosk's own lookups get a turn. */
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
        CountDownLatch done = new CountDownLatch(1);
        AtomicInteger failed = new AtomicInteger();
        NsdManager.RegistrationListener l = new NsdManager.RegistrationListener() {
            @Override public void onRegistrationFailed(NsdServiceInfo i, int c) { failed.set(c == 0 ? -1 : c); done.countDown(); }
            @Override public void onUnregistrationFailed(NsdServiceInfo i, int c) {}
            @Override public void onServiceRegistered(NsdServiceInfo i) { done.countDown(); }
            @Override public void onServiceUnregistered(NsdServiceInfo i) {}
        };
        try {
            nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, l);
        } catch (RuntimeException e) {
            throw new IOException("mDNS advertising " + instance + ": " + e.getMessage());
        }
        try {
            done.await(RESOLVE_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (failed.get() != 0) throw new IOException("mDNS advertising " + instance + " failed (" + failed.get() + ")");
        return () -> {
            try { nsd.unregisterService(l); } catch (IllegalArgumentException ignored) {}
        };
    }
}
