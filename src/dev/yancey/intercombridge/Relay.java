package dev.yancey.intercombridge;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/**
 * Carries one answered call's audio. The kiosk's 80 ms frames go to the Echo as 20 ms frames on a
 * 20 ms clock, with silence whenever the kiosk sends nothing (push to talk, or before its socket is
 * up): an Echo hangs up on a call that goes quiet for 5 s. The Echo's frames are gathered into 80 ms
 * frames for the kiosk.
 */
final class Relay {
    /** Who ended a call. */
    static final String ECHO = "echo", KIOSK = "kiosk", BRIDGE = "bridge";
    /** Put in the call's inbox when the relay ends. */
    static final Object DONE = new Object();

    // The most kiosk audio held for the Echo, 0.5 s: a kiosk that bursts more loses its oldest audio
    // rather than putting the call further behind.
    private static final int BACKLOG_MOST = 16000;

    private final T5Link link;
    private final double toEchoGain, toKioskGain, quietLevel;
    private final BlockingQueue<Object> inbox;
    private final ExecutorService pool;

    private byte[] backlog = new byte[0]; // kiosk audio waiting for the Echo; guarded by this
    private volatile WebSocket ws;
    private volatile long heardAt = System.nanoTime(); // when either side last sent audio above quietLevel
    private volatile boolean done;
    volatile String by = "", why = "";

    Relay(T5Link link, double toEchoDb, double toKioskDb, double quietDbfs, BlockingQueue<Object> inbox, ExecutorService pool) {
        this.link = link;
        this.toEchoGain = gain(toEchoDb);
        this.toKioskGain = gain(toKioskDb);
        this.quietLevel = Short.MAX_VALUE * gain(quietDbfs);
        this.inbox = inbox;
        this.pool = pool;
    }

    static double gain(double db) {
        return Math.pow(10, db / 20);
    }

    boolean done() {
        return done;
    }

    /** How long neither side has sent anything above the quiet level, in ms. */
    long quietMs() {
        return (System.nanoTime() - heardAt) / 1000000;
    }

    private void hear(byte[] pcm, int len) {
        if (rms(pcm, len) > quietLevel) heardAt = System.nanoTime();
    }

    /** Begins sending to the Echo and reading from it. */
    void start() {
        pool.execute(this::pump);
        pool.execute(this::fromEcho);
    }

    /** Adds the kiosk's audio socket: our talk state first, then audio both ways. */
    void attach(WebSocket socket) {
        ws = socket;
        try {
            socket.sendText("{\"type\":\"talk\",\"on\":true}");
        } catch (IOException e) {
            end(KIOSK, "audio socket: " + e.getMessage());
            return;
        }
        pool.execute(() -> fromKiosk(socket));
    }

    void end(String who, String reason) {
        synchronized (this) {
            if (done) return;
            done = true;
            by = who;
            why = reason;
        }
        inbox.offer(DONE);
    }

    /** Hangs up both sides: the kiosk is told unless it was the one that ended the call. */
    void close() {
        end(BRIDGE, "closed");
        WebSocket s = ws;
        if (s != null) {
            if (!KIOSK.equals(by)) {
                try { s.sendText("{\"type\":\"end\"}"); } catch (IOException ignored) {}
            }
            s.close();
        }
        link.close();
    }

    /** Sends the Echo one 20 ms frame every 20 ms. */
    private void pump() {
        byte[] silence = new byte[T5Link.FRAME_BYTES];
        long next = System.nanoTime();
        while (!done) {
            next += TimeUnit.MILLISECONDS.toNanos(20);
            long wait = next - System.nanoTime();
            if (wait > 0) LockSupport.parkNanos(wait); else next = System.nanoTime(); // fell behind: do not burst
            if (done) return;
            if (link.gone) {
                end(ECHO, "the Echo hung up");
                return;
            }
            byte[] out = silence;
            synchronized (this) {
                if (backlog.length >= T5Link.FRAME_BYTES) {
                    out = Arrays.copyOf(backlog, T5Link.FRAME_BYTES);
                    backlog = Arrays.copyOfRange(backlog, T5Link.FRAME_BYTES, backlog.length);
                }
            }
            try {
                link.sendAudio(out);
            } catch (IOException e) {
                end(ECHO, "sending to the Echo: " + e.getMessage());
                return;
            }
        }
    }

    /** Gathers the Echo's frames and sends the kiosk one 80 ms frame per four. */
    private void fromEcho() {
        byte[] gathered = new byte[Ks.FRAME_BYTES];
        int have = 0;
        while (!done) {
            byte[] b;
            try {
                b = link.audio.poll(100, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (b == null) {
                if (link.gone) {
                    end(ECHO, "the Echo hung up");
                    return;
                }
                continue;
            }
            hear(b, b.length);
            for (int off = 0; off < b.length; ) {
                int n = Math.min(b.length - off, Ks.FRAME_BYTES - have);
                System.arraycopy(b, off, gathered, have, n);
                have += n;
                off += n;
                if (have == Ks.FRAME_BYTES) {
                    byte[] chunk = gathered.clone();
                    have = 0;
                    applyGain(chunk, chunk.length, toKioskGain);
                    WebSocket s = ws;
                    if (s == null) continue; // the kiosk's socket is not up yet
                    try {
                        s.send(WebSocket.BINARY, chunk);
                    } catch (IOException e) {
                        end(KIOSK, "sending to the kiosk: " + e.getMessage());
                        return;
                    }
                }
            }
        }
    }

    /** Reads the kiosk's socket: audio for the Echo, and its word that the call is over. */
    private void fromKiosk(WebSocket s) {
        while (!done) {
            WebSocket.Message m;
            try {
                m = s.read();
            } catch (IOException e) {
                end(KIOSK, "the kiosk closed the audio socket");
                return;
            }
            if (m.kind == WebSocket.BINARY) {
                int len = m.data.length & ~1;
                hear(m.data, len);
                applyGain(m.data, len, toEchoGain);
                synchronized (this) {
                    byte[] b = Arrays.copyOf(backlog, backlog.length + len);
                    System.arraycopy(m.data, 0, b, backlog.length, len);
                    int over = b.length - BACKLOG_MOST;
                    if (over > 0) b = Arrays.copyOfRange(b, over + (over & 1), b.length);
                    backlog = b;
                }
            } else if (m.kind == WebSocket.TEXT && "end".equals(Json.str(Json.object(m.data), "type"))) {
                end(KIOSK, "the kiosk hung up");
                return;
            }
            // {"type":"talk"} is the kiosk's push-to-talk state. Nothing to pass on: when it stops
            // talking it stops sending, and the Echo hears the pump's silence.
        }
    }

    /** The root mean square of 16-bit little-endian samples, at int16 scale. */
    static double rms(byte[] pcm, int len) {
        int n = len / 2;
        if (n == 0) return 0;
        double sum = 0;
        for (int i = 0; i + 1 < len; i += 2) {
            double v = (short) ((pcm[i] & 0xff) | (pcm[i + 1] << 8));
            sum += v * v;
        }
        return Math.sqrt(sum / n);
    }

    /** Scales 16-bit little-endian samples in place, clipping at full scale. */
    static void applyGain(byte[] pcm, int len, double gain) {
        if (gain == 1) return;
        for (int i = 0; i + 1 < len; i += 2) {
            double v = Math.round((short) ((pcm[i] & 0xff) | (pcm[i + 1] << 8)) * gain);
            int s = (int) Math.max(Short.MIN_VALUE, Math.min(Short.MAX_VALUE, v));
            pcm[i] = (byte) s;
            pcm[i + 1] = (byte) (s >> 8);
        }
    }
}
