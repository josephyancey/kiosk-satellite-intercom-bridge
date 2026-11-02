package dev.yancey.intercombridge;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import me.jxl.kiosk.plugins.KioskPlugin;
import me.jxl.kiosk.plugins.PluginHost;

/**
 * Runs the intercom bridge inside Kiosk Satellite, so Kiosk Satellite kiosks and TECHO5 Echos can
 * call and announce to each other. Install it on one kiosk, or on several: only one bridge runs on
 * the network at a time, and another takes over when it stops.
 */
public final class IntercomBridgePlugin implements KioskPlugin {
    static final String VERSION = "1.0.0";
    private static final long EVERY_MS = 30000;

    private PluginHost host;
    private ExecutorService pool;
    private Runner runner;
    private Thread thread;
    private Map<String, Object> running; // the settings the runner was started with

    @Override
    public void start(PluginHost host, Map<String, Object> settings) {
        this.host = host;
        configure(settings);
    }

    @Override
    public synchronized void configure(Map<String, Object> settings) {
        if (settings.equals(running)) return;
        halt();
        running = settings;
        Bridge.Config cfg = new Bridge.Config();
        cfg.intercomKey = str(settings, "intercomKey").trim();
        cfg.houseWord = str(settings, "houseWord");
        if (cfg.intercomKey.isEmpty() || cfg.houseWord.isEmpty()) {
            report("", "Needs the intercom key and the house word");
            return;
        }
        Context context = context();
        if (context == null) {
            report("off", "Could not reach Android's mDNS service");
            return;
        }
        cfg.advertise = str(settings, "advertiseAddress").trim();
        if (cfg.advertise.isEmpty()) cfg.advertise = ownAddress();
        if (cfg.advertise.isEmpty()) {
            report("off", "No network address yet; set This kiosk's address");
            return;
        }
        File dir = new File(context.getNoBackupFilesDir(), "intercom-bridge");
        cfg.stateFile = new File(dir, "state.json");
        cfg.nameSuffix = str(settings, "nameSuffix");
        cfg.silenceHangupMs = (long) (num(settings, "silenceHangup", 0) * 1000);
        cfg.quietDbfs = num(settings, "quietLevel", -55);
        cfg.toEchoDb = num(settings, "gainToEcho", 0);
        cfg.toKioskDb = num(settings, "gainToKiosk", 0);
        cfg.portLow = (int) num(settings, "portLow", 41000);
        cfg.portHigh = (int) num(settings, "portHigh", 41099);
        cfg.version = VERSION;
        if (cfg.portHigh < cfg.portLow) {
            report("off", "The last stand-in port is below the first");
            return;
        }
        AtomicInteger n = new AtomicInteger();
        ThreadFactory daemons = r -> {
            Thread t = new Thread(r, "intercom-bridge-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
        pool = Executors.newCachedThreadPool(daemons);
        Bridge.Log log = new Bridge.Log() {
            @Override public void info(String m) { say(m); }
            @Override public void warn(String m) { say(m); }
        };
        runner = new Runner(cfg, new NsdMdns(context), pool, log, this::report, bridgeId(dir),
                (int) num(settings, "statusPort", 8790), EVERY_MS);
        report("", "Looking for another bridge");
        thread = daemons.newThread(runner::run);
        thread.start();
    }

    @Override
    public void execute(String command, Map<String, Object> arguments) {}

    @Override
    public void onEvent(String event, Map<String, Object> payload) {}

    @Override
    public synchronized void stop() {
        halt();
        running = null;
        try { host.removeStatusTile("bridge"); } catch (RuntimeException ignored) {}
    }

    /** Stops the runner and every call and stand-in, within the host's three seconds. */
    private void halt() {
        if (runner == null) return;
        runner.stop();
        thread.interrupt();
        try {
            thread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        pool.shutdownNow();
        runner = null;
        thread = null;
        pool = null;
    }

    private void report(String level, String text) {
        PluginHost h = host;
        if (h == null) return;
        try {
            h.status(text, "off".equals(level));
            h.publishStatusTile("bridge", "Intercom bridge", level, text.length() > 80 ? text.substring(0, 77) + "..." : text);
        } catch (RuntimeException ignored) {
            // an older Kiosk Satellite, or the plugin is stopping
        }
    }

    private void say(String message) {
        PluginHost h = host;
        if (h == null) return;
        try {
            h.log(message);
        } catch (RuntimeException ignored) {
        }
    }

    /** The app's context, which SDK 1 does not hand plugins: Android keeps it for the process. */
    private static Context context() {
        try {
            return (Context) Class.forName("android.app.ActivityThread").getMethod("currentApplication").invoke(null);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    /** This device's IPv4 address on the local network, Wi-Fi or Ethernet first. */
    static String ownAddress() {
        String fallback = "";
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (!(a instanceof Inet4Address) || !a.isSiteLocalAddress()) continue;
                    String name = ni.getName();
                    if (name.startsWith("wlan") || name.startsWith("eth")) return a.getHostAddress();
                    if (fallback.isEmpty()) fallback = a.getHostAddress();
                }
            }
        } catch (IOException | RuntimeException ignored) {
        }
        return fallback;
    }

    /** This bridge's id, kept so it stays the same across restarts. */
    private static String bridgeId(File dir) {
        File f = new File(dir, "bridge-id");
        try {
            String id = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim();
            if (id.matches("[0-9a-f]{16}")) return id;
        } catch (IOException ignored) {
        }
        String id = Crypto.hex(Crypto.random(8));
        dir.mkdirs();
        try (FileOutputStream o = new FileOutputStream(f)) {
            o.write(id.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
        return id;
    }

    private static String str(Map<String, Object> s, String k) {
        Object v = s.get(k);
        return v instanceof String ? (String) v : "";
    }

    private static double num(Map<String, Object> s, String k, double def) {
        Object v = s.get(k);
        return v instanceof Number ? ((Number) v).doubleValue() : def;
    }
}
