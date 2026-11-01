package dev.yancey.intercombridge;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * One TECHO5 intercom call: an HTTP upgrade to /intercom, the sealed handshake keyed by the house
 * word, then one-byte typed messages. It follows TECHO5's echod/internal/feature/phone/intercom.go.
 * One thread reads the link: audio goes to {@link #audio}, every other message to the inbox the
 * call was made with, and {@link #GONE} goes there when the other end hangs up.
 */
final class T5Link {
    static final String PATH = "/intercom";
    static final String PROTOCOL = "techo5-intercom/1"; // the Upgrade asked for, and the handshake's prologue
    private static final String KEY_LABEL = "techo5-intercom psk";

    /** One audio message: 20 ms of 16 kHz mono PCM16, little-endian. */
    static final int FRAME_BYTES = 640;
    private static final int NAME_MOST = 40;

    static final int HANDSHAKE_MS = 5000, RING_MS = 30000;
    private static final int WAIT_QUIET_MS = RING_MS + 10000; // before an answer, only a few messages come
    private static final int TALK_QUIET_MS = 5000; // once answered, audio every 20 ms

    static final byte HELLO = 'H', RINGING = 'R', BUSY = 'B', ANSWER = 'A', DECLINE = 'D', NOT_NOW = 'N', AUDIO = 'S', BYE = 'X';

    /** Put in the inbox when the link ends. */
    static final Object GONE = new Object() {
        @Override public String toString() { return "gone"; }
    };

    static byte[] key(String houseWord) {
        return Sealed.key(KEY_LABEL, houseWord);
    }

    private final Socket socket;
    private final Sealed c;
    private final BlockingQueue<Object> inbox;
    final BlockingQueue<byte[]> audio = new ArrayBlockingQueue<>(25);
    volatile boolean gone;
    private volatile boolean talking, closed;

    private T5Link(Socket socket, Sealed c, BlockingQueue<Object> inbox) {
        this.socket = socket;
        this.c = c;
        this.inbox = inbox;
        Thread t = new Thread(this::read, "t5-link");
        t.setDaemon(true);
        t.start();
    }

    private void read() {
        try {
            byte[] hdr = new byte[3];
            while (true) {
                socket.setSoTimeout(talking ? TALK_QUIET_MS : WAIT_QUIET_MS);
                c.readFully(hdr);
                int n = (hdr[1] & 0xff) << 8 | (hdr[2] & 0xff);
                if (n > FRAME_BYTES) return;
                byte[] b = new byte[n];
                c.readFully(b);
                if (hdr[0] == BYE) return;
                if (hdr[0] == AUDIO) {
                    audio.offer(b); // a reader behind loses this frame rather than everything after it late
                    continue;
                }
                inbox.offer(hdr[0]);
            }
        } catch (IOException ignored) {
            // the other end hung up, or went quiet too long
        } finally {
            gone = true;
            inbox.offer(GONE);
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private void writeMsg(byte t, byte[] payload) throws IOException {
        byte[] b = new byte[3 + payload.length];
        b[0] = t;
        b[1] = (byte) (payload.length >>> 8);
        b[2] = (byte) payload.length;
        System.arraycopy(payload, 0, b, 3, payload.length);
        c.write(b);
    }

    /** Sends a control message. */
    void say(byte t) throws IOException {
        writeMsg(t, new byte[0]);
    }

    /** Sends one 20 ms frame. */
    void sendAudio(byte[] frame) throws IOException {
        writeMsg(AUDIO, frame);
    }

    /** Marks the call answered, which shortens how long the other end may go quiet. */
    void talk() {
        talking = true;
    }

    /** Says goodbye if the other end is still listening, and hangs up either way. */
    void close() {
        synchronized (this) {
            if (closed) return;
            closed = true;
        }
        try {
            socket.setSoTimeout(500);
            writeMsg(BYE, new byte[0]);
        } catch (IOException ignored) {
        }
        try { socket.close(); } catch (IOException ignored) {}
    }

    /** A caller's name made safe to show and pass on: printable and not too long. */
    static String shownName(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().filter(cp -> cp != 0xFFFD && !Character.isISOControl(cp) && Character.isDefined(cp)
                && Character.getType(cp) != Character.FORMAT && Character.getType(cp) != Character.PRIVATE_USE
                && Character.getType(cp) != Character.SURROGATE).forEach(b::appendCodePoint);
        String out = b.toString().trim();
        if (out.codePointCount(0, out.length()) > NAME_MOST) out = out.substring(0, out.offsetByCodePoints(0, NAME_MOST));
        return out.isEmpty() ? "Another room" : out;
    }

    /**
     * Calls a device: the upgrade, the handshake, and Hello with the caller's name. It returns once
     * the call is sent; the device's answer (Ringing, Busy, ...) arrives in the inbox.
     */
    static T5Link dial(String address, int port, byte[] key, String callerName, BlockingQueue<Object> inbox) throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(address, port), HANDSHAKE_MS);
            s.setSoTimeout(HANDSHAKE_MS);
            s.setTcpNoDelay(true);
            OutputStream out = s.getOutputStream();
            out.write(("GET " + PATH + " HTTP/1.1\r\nHost: " + address + "\r\nUpgrade: " + PROTOCOL
                    + "\r\nConnection: Upgrade\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream());
            Http.Response resp = Http.readResponseHead(in);
            if (resp.status != 101) throw new IOException("the device takes no calls (HTTP " + resp.status + ")");
            Sealed c = Sealed.client(in, out, PROTOCOL, key);
            T5Link l = new T5Link(s, c, inbox);
            l.writeMsg(HELLO, shownName(callerName).getBytes(StandardCharsets.UTF_8));
            return l;
        } catch (IOException e) {
            s.close();
            throw e;
        }
    }

    /** What {@link #accept} hands back: the link and who is calling. */
    static final class Accepted {
        final T5Link link;
        final String caller;
        Accepted(T5Link link, String caller) { this.link = link; this.caller = caller; }
    }

    /**
     * Takes a device's call on a request already read: answers the upgrade, does the handshake and
     * reads its Hello. The request must have asked for {@link #PROTOCOL}.
     */
    static Accepted accept(Http.Request r, byte[] key, BlockingQueue<Object> inbox) throws IOException {
        Socket s = r.socket;
        try {
            s.setSoTimeout(HANDSHAKE_MS);
            s.setTcpNoDelay(true);
            r.out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + PROTOCOL + "\r\nConnection: Upgrade\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            r.out.flush();
            Sealed c = Sealed.server(r.in, r.out, PROTOCOL, key);
            byte[] hdr = new byte[3];
            c.readFully(hdr);
            int n = (hdr[1] & 0xff) << 8 | (hdr[2] & 0xff);
            if (hdr[0] != HELLO || n > FRAME_BYTES) throw new IOException("the caller did not say who it is");
            byte[] name = new byte[n];
            c.readFully(name);
            return new Accepted(new T5Link(s, c, inbox), shownName(new String(name, StandardCharsets.UTF_8)));
        } catch (IOException e) {
            s.close();
            throw e;
        }
    }
}
