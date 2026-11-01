package dev.yancey.intercombridge;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * A connection after TECHO5's handshake, Noise_NNpsk0_25519_ChaChaPoly_SHA256, as TECHO5's
 * sealed.go does it: each record is a 4-byte big-endian length and a sealed message. What is
 * written is encrypted; what is read is decrypted and checked.
 */
final class Sealed {
    static final class KeyException extends IOException {
        KeyException() { super("the other end has a different key"); }
    }

    private static final int RECORD_MAX = 60000, WIRE_MAX = RECORD_MAX + 64, HANDSHAKE_MAX = 256;
    private static final byte[] NAME = "Noise_NNpsk0_25519_ChaChaPoly_SHA256".getBytes(StandardCharsets.UTF_8);

    /** Turns a shared word into the 32 bytes Noise wants. label keeps one word's uses apart. */
    static byte[] key(String label, String word) {
        return Crypto.sha256(label + ":" + word);
    }

    /** One direction's cipher: a key and a counter. */
    private static final class Cipher {
        final byte[] k;
        long n;
        Cipher(byte[] k) { this.k = k; }
        byte[] nonce() {
            byte[] b = new byte[12];
            for (int i = 0; i < 8; i++) b[4 + i] = (byte) (n >>> (8 * i));
            n++;
            return b;
        }
    }

    /** Noise's symmetric state for the handshake. */
    private static final class Symmetric {
        byte[] ck, h, k;
        long n;

        Symmetric(byte[] prologue) {
            h = NAME.length <= 32 ? Arrays.copyOf(NAME, 32) : Crypto.sha256(NAME);
            ck = h.clone();
            mixHash(prologue);
        }

        void mixHash(byte[] d) { h = Crypto.sha256(h, d); }

        byte[][] hkdf(byte[] ikm, int outs) {
            byte[] temp = Crypto.hmac(ck, ikm);
            byte[][] out = new byte[outs][];
            byte[] prev = new byte[0];
            for (int i = 0; i < outs; i++) {
                prev = Crypto.hmac(temp, prev, new byte[] {(byte) (i + 1)});
                out[i] = prev;
            }
            return out;
        }

        void mixKey(byte[] ikm) {
            byte[][] o = hkdf(ikm, 2);
            ck = o[0];
            k = o[1];
            n = 0;
        }

        void mixKeyAndHash(byte[] ikm) {
            byte[][] o = hkdf(ikm, 3);
            ck = o[0];
            mixHash(o[1]);
            k = o[2];
            n = 0;
        }

        byte[] nonce() {
            byte[] b = new byte[12];
            for (int i = 0; i < 8; i++) b[4 + i] = (byte) (n >>> (8 * i));
            n++;
            return b;
        }

        byte[] encryptAndHash(byte[] p) {
            byte[] c = Crypto.seal(k, nonce(), h, p);
            mixHash(c);
            return c;
        }

        byte[] decryptAndHash(byte[] c) throws KeyException {
            byte[] p = Crypto.open(k, nonce(), h, c);
            if (p == null) throw new KeyException();
            mixHash(c);
            return p;
        }

        Cipher[] split() {
            byte[][] o = hkdf(new byte[0], 2);
            return new Cipher[] {new Cipher(o[0]), new Cipher(o[1])};
        }
    }

    private final InputStream in;
    private final OutputStream out;
    private final Cipher send, recv;
    private byte[] rbuf = new byte[0];
    private int rpos;

    private Sealed(InputStream in, OutputStream out, Cipher send, Cipher recv) {
        this.in = in;
        this.out = out;
        this.send = send;
        this.recv = recv;
    }

    /** The side that opened the connection. */
    static Sealed client(InputStream in, OutputStream out, String prologue, byte[] psk) throws IOException {
        Symmetric s = new Symmetric(prologue.getBytes(StandardCharsets.UTF_8));
        s.mixKeyAndHash(psk);
        byte[] e = Crypto.random(32), ePub = Crypto.x25519(e, Crypto.BASE);
        s.mixHash(ePub);
        s.mixKey(ePub);
        writeFrame(out, concat(ePub, s.encryptAndHash(new byte[0])));
        byte[] reply = readFrame(in, HANDSHAKE_MAX);
        if (reply.length < 32) throw new KeyException();
        byte[] re = Arrays.copyOf(reply, 32);
        s.mixHash(re);
        s.mixKey(re);
        s.mixKey(Crypto.x25519(e, re));
        s.decryptAndHash(Arrays.copyOfRange(reply, 32, reply.length));
        Cipher[] c = s.split();
        return new Sealed(in, out, c[0], c[1]);
    }

    /** The side that took the connection. */
    static Sealed server(InputStream in, OutputStream out, String prologue, byte[] psk) throws IOException {
        Symmetric s = new Symmetric(prologue.getBytes(StandardCharsets.UTF_8));
        s.mixKeyAndHash(psk);
        byte[] first = readFrame(in, HANDSHAKE_MAX);
        if (first.length < 32) throw new KeyException();
        byte[] re = Arrays.copyOf(first, 32);
        s.mixHash(re);
        s.mixKey(re);
        s.decryptAndHash(Arrays.copyOfRange(first, 32, first.length));
        byte[] e = Crypto.random(32), ePub = Crypto.x25519(e, Crypto.BASE);
        s.mixHash(ePub);
        s.mixKey(ePub);
        s.mixKey(Crypto.x25519(e, re));
        writeFrame(out, concat(ePub, s.encryptAndHash(new byte[0])));
        Cipher[] c = s.split();
        return new Sealed(in, out, c[1], c[0]);
    }

    synchronized void write(byte[] p) throws IOException {
        for (int off = 0; off < p.length; off += RECORD_MAX) {
            byte[] chunk = Arrays.copyOfRange(p, off, Math.min(p.length, off + RECORD_MAX));
            writeFrame(out, Crypto.seal(send.k, send.nonce(), new byte[0], chunk));
        }
    }

    /** Reads exactly b.length bytes of plaintext. */
    void readFully(byte[] b) throws IOException {
        int got = 0;
        while (got < b.length) {
            if (rpos == rbuf.length) {
                byte[] pt = Crypto.open(recv.k, recv.nonce(), new byte[0], readFrame(in, WIRE_MAX));
                if (pt == null) throw new IOException("sealed: a record that does not check out");
                rbuf = pt;
                rpos = 0;
            }
            int n = Math.min(b.length - got, rbuf.length - rpos);
            System.arraycopy(rbuf, rpos, b, got, n);
            rpos += n;
            got += n;
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    private static void writeFrame(OutputStream out, byte[] b) throws IOException {
        byte[] f = new byte[4 + b.length];
        f[0] = (byte) (b.length >>> 24); f[1] = (byte) (b.length >>> 16); f[2] = (byte) (b.length >>> 8); f[3] = (byte) b.length;
        System.arraycopy(b, 0, f, 4, b.length);
        out.write(f);
        out.flush();
    }

    private static byte[] readFrame(InputStream in, int most) throws IOException {
        DataInputStream d = new DataInputStream(in);
        int n;
        try {
            n = d.readInt();
        } catch (EOFException e) {
            throw new EOFException("the connection closed");
        }
        if (n <= 0 || n > most) throw new IOException("sealed: a record of " + n + " bytes");
        byte[] b = new byte[n];
        d.readFully(b);
        return b;
    }
}
