package dev.yancey.intercombridge;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Just enough HTTP/1.1 for the intercoms: a server whose handlers may take the connection over for
 * an upgrade, and a client for small JSON and audio requests.
 */
final class Http {
    private Http() {}

    private static final int HEAD_MOST = 16 << 10;
    static final int BODY_MOST = 2 << 20; // a 20 s announcement is 640 KB
    /** The most a JSON request needs. A bigger body waits for one of the BIG_BODIES permits. */
    static final int SMALL_BODY = 64 << 10;

    // Everything below is read before the sender is checked, so it is bounded: a host on the network
    // with no key must not be able to fill a small device's memory or threads.
    private static final Semaphore BIG_BODIES = new Semaphore(2);
    private static final Semaphore CONNECTIONS = new Semaphore(128); // across every port
    private static final int PORT_CONNECTIONS = 16;
    /** How long a request, or the wait for the next one on a kept-alive connection, may take in all. */
    private static final long REQUEST_MOST_MS = 20000;

    /** Ends a request that runs past its deadline, however slowly its bytes trickle in. */
    private static final class Deadline extends FilterInputStream {
        private volatile long started;
        private volatile boolean on;

        Deadline(InputStream in) { super(in); }

        void start() {
            started = System.nanoTime();
            on = true;
        }

        void off() { on = false; }

        private void check() throws IOException {
            if (on && System.nanoTime() - started > REQUEST_MOST_MS * 1_000_000L) throw new IOException("a request too slow");
        }

        @Override public int read() throws IOException { check(); return super.read(); }

        @Override public int read(byte[] b, int off, int len) throws IOException { check(); return super.read(b, off, len); }
    }

    static final class Request {
        String method, path, query = "";
        final Map<String, String> headers = new LinkedHashMap<>(); // keys in lower case
        byte[] body = new byte[0];
        Socket socket;
        InputStream in;
        OutputStream out;
        boolean taken; // the handler took the connection over

        String header(String name) {
            String v = headers.get(name.toLowerCase(Locale.ROOT));
            return v == null ? "" : v;
        }

        String param(String name) {
            for (String kv : query.split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0 && unescape(kv.substring(0, eq)).equals(name)) return unescape(kv.substring(eq + 1));
            }
            return "";
        }

        /**
         * Says the peer has proved itself, so the connection it took over may outlast the deadline
         * every request has until then: a call runs as long as it lasts.
         */
        void trusted() {
            if (in instanceof Deadline) ((Deadline) in).off();
        }

        String remoteHost() {
            InetAddress a = socket.getInetAddress();
            return a == null ? "" : a.getHostAddress();
        }

        void respond(int status, Map<String, String> headers, byte[] body) throws IOException {
            StringBuilder h = new StringBuilder("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n");
            if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) h.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            h.append("Content-Length: ").append(body.length).append("\r\n\r\n");
            out.write(h.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
        }

        void json(int status, Object v) throws IOException {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("Content-Type", "application/json");
            respond(status, h, (Json.write(v) + "\n").getBytes(StandardCharsets.UTF_8));
        }

        void text(int status, String s) throws IOException {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("Content-Type", "text/plain; charset=utf-8");
            respond(status, h, (s + "\n").getBytes(StandardCharsets.UTF_8));
        }
    }

    interface Handler {
        void handle(Request r) throws IOException;
    }

    static String reason(int status) {
        switch (status) {
            case 101: return "Switching Protocols";
            case 200: return "OK";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 409: return "Conflict";
            default: return "Status";
        }
    }

    static String escape(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String unescape(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (IllegalArgumentException | IOException e) {
            return s;
        }
    }

    /** Reads one CRLF-terminated line, without the line end. Null at the end of the stream. */
    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') break;
            if (b.size() > HEAD_MOST) throw new IOException("a header line too long");
            b.write(c);
        }
        if (c == -1 && b.size() == 0) return null;
        String s = new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    private static void readHeaders(InputStream in, Map<String, String> into) throws IOException {
        for (int n = 0; ; n++) {
            String line = readLine(in);
            if (line == null) throw new IOException("the connection closed in the headers");
            if (line.isEmpty()) return;
            if (n > 100) throw new IOException("too many headers");
            int colon = line.indexOf(':');
            if (colon > 0) into.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT), line.substring(colon + 1).trim());
        }
    }

    static byte[] readN(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        for (int got = 0; got < n; ) {
            int r = in.read(b, got, n - got);
            if (r < 0) throw new IOException("the connection closed early");
            got += r;
        }
        return b;
    }

    /**
     * A server on one port. Each connection gets a thread from pool, up to PORT_CONNECTIONS on the
     * port and CONNECTIONS in all; more are closed at once. Request bodies over bodyMost are refused.
     */
    static final class Server {
        private final ServerSocket ss;
        private final Handler handler;
        private final ExecutorService pool;
        private final int bodyMost;
        private final Semaphore open = new Semaphore(PORT_CONNECTIONS);

        Server(String listen, int port, Handler handler, ExecutorService pool) throws IOException {
            this(listen, port, handler, pool, SMALL_BODY);
        }

        Server(String listen, int port, Handler handler, ExecutorService pool, int bodyMost) throws IOException {
            ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(listen == null || listen.isEmpty() ? new InetSocketAddress(port) : new InetSocketAddress(listen, port));
            this.handler = handler;
            this.pool = pool;
            this.bodyMost = Math.min(bodyMost, BODY_MOST);
            pool.execute(this::accept);
        }

        int port() {
            return ss.getLocalPort();
        }

        private void accept() {
            while (!ss.isClosed()) {
                Socket s;
                try {
                    s = ss.accept();
                } catch (IOException e) {
                    if (ss.isClosed()) return;
                    continue;
                }
                if (!open.tryAcquire()) {
                    closeQuietly(s);
                    continue;
                }
                if (!CONNECTIONS.tryAcquire()) {
                    open.release();
                    closeQuietly(s);
                    continue;
                }
                try {
                    pool.execute(() -> {
                        try {
                            serve(s);
                        } finally {
                            CONNECTIONS.release();
                            open.release();
                        }
                    });
                } catch (RejectedExecutionException e) {
                    CONNECTIONS.release();
                    open.release();
                    closeQuietly(s);
                    if (ss.isClosed()) return;
                }
            }
        }

        private static void closeQuietly(Socket s) {
            try { s.close(); } catch (IOException ignored) {}
        }

        private void serve(Socket s) {
            boolean taken = false;
            boolean big = false;
            try {
                s.setSoTimeout(15000);
                Deadline in = new Deadline(new BufferedInputStream(s.getInputStream()));
                OutputStream out = s.getOutputStream();
                while (true) {
                    in.start();
                    String line = readLine(in);
                    if (line == null) return;
                    String[] parts = line.split(" ");
                    if (parts.length < 3) return;
                    Request r = new Request();
                    r.method = parts[0];
                    int q = parts[1].indexOf('?');
                    r.path = q < 0 ? parts[1] : parts[1].substring(0, q);
                    if (q >= 0) r.query = parts[1].substring(q + 1);
                    readHeaders(in, r.headers);
                    String len = r.header("content-length");
                    if (!len.isEmpty()) {
                        int n = Integer.parseInt(len);
                        if (n < 0 || n > bodyMost) return;
                        if (n > SMALL_BODY) {
                            if (!BIG_BODIES.tryAcquire(5, TimeUnit.SECONDS)) return;
                            big = true;
                        }
                        r.body = readN(in, n);
                    } else if (r.header("transfer-encoding").equalsIgnoreCase("chunked")) {
                        r.body = readChunked(in, Math.min(bodyMost, SMALL_BODY));
                    }
                    r.socket = s;
                    r.in = in;
                    r.out = out;
                    handler.handle(r);
                    if (big) {
                        big = false;
                        BIG_BODIES.release();
                    }
                    if (r.taken) {
                        taken = true;
                        return;
                    }
                    if (r.header("connection").equalsIgnoreCase("close")) return;
                }
            } catch (IOException | RuntimeException | StackOverflowError ignored) {
                // whatever a peer sends, the connection ends here and the app runs on
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                if (big) BIG_BODIES.release();
                if (!taken) closeQuietly(s);
            }
        }

        void close() {
            try { ss.close(); } catch (IOException ignored) {}
        }
    }

    private static byte[] readChunked(InputStream in, int most) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        while (true) {
            String size = readLine(in);
            if (size == null) throw new IOException("the connection closed in a chunk");
            int semi = size.indexOf(';');
            int n;
            try {
                n = Integer.parseInt((semi < 0 ? size : size.substring(0, semi)).trim(), 16);
            } catch (NumberFormatException e) {
                throw new IOException("a bad chunk size");
            }
            if (n == 0) {
                while (true) {
                    String t = readLine(in);
                    if (t == null || t.isEmpty()) return b.toByteArray();
                }
            }
            if (n < 0 || n > most - b.size()) throw new IOException("a body too large");
            b.write(readN(in, n));
            readLine(in);
        }
    }

    static final class Response {
        int status;
        final Map<String, String> headers = new LinkedHashMap<>();
        byte[] body = new byte[0];

        String header(String name) {
            String v = headers.get(name.toLowerCase(Locale.ROOT));
            return v == null ? "" : v;
        }
    }

    /** Reads a response's status line and headers, leaving the body in the stream. */
    static Response readResponseHead(InputStream in) throws IOException {
        String line = readLine(in);
        if (line == null) throw new IOException("no response");
        String[] parts = line.split(" ", 3);
        if (parts.length < 2 || !parts[0].startsWith("HTTP/")) throw new IOException("not an HTTP response");
        Response r = new Response();
        try {
            r.status = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IOException("not an HTTP response");
        }
        readHeaders(in, r.headers);
        return r;
    }

    /** One request on a new connection, which is closed after the response. */
    static Response request(String method, String host, int port, String pathAndQuery, Map<String, String> headers,
            byte[] body, int timeoutMs) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            StringBuilder h = new StringBuilder(method).append(' ').append(pathAndQuery).append(" HTTP/1.1\r\n");
            h.append("Host: ").append(hostPort(host, port)).append("\r\nConnection: close\r\n");
            if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) h.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            if (body != null) h.append("Content-Length: ").append(body.length).append("\r\n");
            h.append("\r\n");
            OutputStream out = s.getOutputStream();
            out.write(h.toString().getBytes(StandardCharsets.ISO_8859_1));
            if (body != null) out.write(body);
            out.flush();
            InputStream in = new BufferedInputStream(s.getInputStream());
            Response r = readResponseHead(in);
            String len = r.header("content-length");
            if (r.status == 204 || r.status == 304 || method.equals("HEAD")) return r;
            if (!len.isEmpty()) {
                int n = Integer.parseInt(len);
                if (n < 0 || n > BODY_MOST) throw new IOException("a body too large");
                r.body = readN(in, n);
            } else if (r.header("transfer-encoding").equalsIgnoreCase("chunked")) {
                r.body = readChunked(in, BODY_MOST);
            } else {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                for (int n; (n = in.read(buf)) > 0; ) {
                    if (n > BODY_MOST - b.size()) throw new IOException("a body too large");
                    b.write(buf, 0, n);
                }
                r.body = b.toByteArray();
            }
            return r;
        } catch (NumberFormatException e) {
            throw new IOException("a bad response");
        }
    }

    static String hostPort(String host, int port) {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }
}
