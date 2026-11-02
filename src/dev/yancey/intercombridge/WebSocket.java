package dev.yancey.intercombridge;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;

/** A WebSocket (RFC 6455), either end: the kiosks' call audio runs over one. */
final class WebSocket {
    static final int TEXT = 1, BINARY = 2, CLOSE = 8, PING = 9, PONG = 10;
    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final int READ_MOST = 64 << 10;

    /** One message read. */
    static final class Message {
        final int kind;
        final byte[] data;
        Message(int kind, byte[] data) { this.kind = kind; this.data = data; }
        String text() { return new String(data, StandardCharsets.UTF_8); }
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final boolean client; // a client masks what it sends
    private volatile boolean closed;

    private WebSocket(Socket socket, InputStream in, OutputStream out, boolean client) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.client = client;
    }

    private static String accept(String key) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest((key + GUID).getBytes(StandardCharsets.ISO_8859_1));
            return Base64.getEncoder().encodeToString(d);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Opens a socket to ws://host:port/pathAndQuery. */
    static WebSocket dial(String host, int port, String pathAndQuery, int timeoutMs) throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            s.setTcpNoDelay(true);
            String key = Base64.getEncoder().encodeToString(Crypto.random(16));
            OutputStream out = s.getOutputStream();
            out.write(("GET " + pathAndQuery + " HTTP/1.1\r\nHost: " + Http.hostPort(host, port)
                    + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key
                    + "\r\nSec-WebSocket-Version: 13\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream());
            Http.Response r = Http.readResponseHead(in);
            if (r.status != 101) throw new IOException("the kiosk refused the audio socket (HTTP " + r.status + ")");
            if (!accept(key).equals(r.header("sec-websocket-accept"))) throw new IOException("a bad WebSocket handshake");
            s.setSoTimeout(0);
            return new WebSocket(s, in, out, true);
        } catch (IOException e) {
            s.close();
            throw e;
        }
    }

    /** Answers an upgrade request with the socket. */
    static WebSocket upgrade(Http.Request r) throws IOException {
        String key = r.header("sec-websocket-key");
        if (key.isEmpty() || !r.header("upgrade").equalsIgnoreCase("websocket")) {
            r.json(400, new LinkedHashMap<String, Object>());
            return null;
        }
        r.out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                + accept(key) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        r.out.flush();
        r.taken = true;
        r.trusted(); // callers check the call token first
        r.socket.setSoTimeout(0);
        r.socket.setTcpNoDelay(true);
        return new WebSocket(r.socket, r.in, r.out, false);
    }

    void setReadTimeout(int ms) throws IOException {
        socket.setSoTimeout(ms);
    }

    synchronized void send(int kind, byte[] data) throws IOException {
        if (closed && kind != CLOSE) throw new IOException("the audio socket is closed");
        ByteArrayOutputStream f = new ByteArrayOutputStream(data.length + 14);
        f.write(0x80 | kind);
        int mask = client ? 0x80 : 0;
        if (data.length < 126) {
            f.write(mask | data.length);
        } else if (data.length < 65536) {
            f.write(mask | 126);
            f.write(data.length >>> 8);
            f.write(data.length);
        } else {
            f.write(mask | 127);
            for (int i = 7; i >= 0; i--) f.write((int) ((long) data.length >>> (8 * i)));
        }
        if (client) {
            byte[] m = Crypto.random(4);
            f.write(m, 0, 4);
            byte[] masked = new byte[data.length];
            for (int i = 0; i < data.length; i++) masked[i] = (byte) (data[i] ^ m[i & 3]);
            f.write(masked, 0, masked.length);
        } else {
            f.write(data, 0, data.length);
        }
        out.write(f.toByteArray());
        out.flush();
    }

    void sendText(String s) throws IOException {
        send(TEXT, s.getBytes(StandardCharsets.UTF_8));
    }

    /** Reads the next text or binary message, answering pings on the way. */
    Message read() throws IOException {
        ByteArrayOutputStream msg = null;
        int kind = 0;
        while (true) {
            int b0 = in.read(), b1 = in.read();
            if (b0 < 0 || b1 < 0) throw new IOException("the audio socket closed");
            boolean fin = (b0 & 0x80) != 0;
            int op = b0 & 0x0f;
            long len = b1 & 0x7f;
            if (len == 126) {
                len = (in.read() & 0xff) << 8 | (in.read() & 0xff);
            } else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) len = len << 8 | (in.read() & 0xff);
            }
            if (len < 0 || len > READ_MOST) throw new IOException("a WebSocket message too large"); // 64-bit lengths can come in negative
            byte[] m = (b1 & 0x80) != 0 ? Http.readN(in, 4) : null;
            byte[] p = Http.readN(in, (int) len);
            if (m != null) for (int i = 0; i < p.length; i++) p[i] ^= m[i & 3];
            switch (op) {
                case CLOSE:
                    close();
                    throw new IOException("the audio socket closed");
                case PING:
                    send(PONG, p);
                    continue;
                case PONG:
                    continue;
                case 0:
                    if (msg == null) throw new IOException("a continuation with no message");
                    break;
                default:
                    msg = new ByteArrayOutputStream();
                    kind = op;
            }
            msg.write(p, 0, p.length);
            if (msg.size() > READ_MOST) throw new IOException("a WebSocket message too large");
            if (fin) return new Message(kind, msg.toByteArray());
        }
    }

    /** Sends a normal close and closes the connection. */
    void close() {
        synchronized (this) {
            if (closed) return;
            closed = true;
        }
        try {
            socket.setSoTimeout(500);
            send(CLOSE, new byte[] {0x03, (byte) 0xe8});
        } catch (IOException ignored) {
        }
        try { socket.close(); } catch (IOException ignored) {}
    }
}
