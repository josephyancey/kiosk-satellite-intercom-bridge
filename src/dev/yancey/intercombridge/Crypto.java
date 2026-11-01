package dev.yancey.intercombridge;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The primitives TECHO5's intercom uses: X25519, ChaCha20-Poly1305 (RFC 8439) and SHA-256. They
 * are written out here, X25519 after TweetNaCl, because Android only ships them from API 33 and
 * under names that differ from the JDK's.
 */
final class Crypto {
    private Crypto() {}

    static final SecureRandom RANDOM = new SecureRandom();

    static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) d.update(p);
            return d.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sha256(String s) {
        return sha256(s.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] p : parts) mac.update(p);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return s.toString();
    }

    static byte[] unhex(String s) {
        if (s.length() % 2 != 0) return null;
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16), lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) return null;
            b[i] = (byte) (hi << 4 | lo);
        }
        return b;
    }

    // ---- X25519 ----

    private static final long[] A24 = {0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static final byte[] BASE = new byte[32];
    static { BASE[0] = 9; }

    private static void car(long[] o) {
        for (int i = 0; i < 16; i++) {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            if (i < 15) o[i + 1] += c - 1; else o[0] += 38 * (c - 1);
            o[i] -= c << 16;
        }
    }

    private static void sel(long[] p, long[] q, int b) {
        long c = ~(b - 1);
        for (int i = 0; i < 16; i++) {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void pack(byte[] o, long[] n) {
        long[] m = new long[16], t = Arrays.copyOf(n, 16);
        car(t); car(t); car(t);
        for (int j = 0; j < 2; j++) {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            int b = (int) ((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            sel(t, m, 1 - b);
        }
        for (int i = 0; i < 16; i++) {
            o[2 * i] = (byte) t[i];
            o[2 * i + 1] = (byte) (t[i] >> 8);
        }
    }

    private static void add(long[] o, long[] a, long[] b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }

    private static void sub(long[] o, long[] a, long[] b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

    private static void mul(long[] o, long[] a, long[] b) {
        long[] t = new long[31];
        for (int i = 0; i < 16; i++) for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
        for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
        System.arraycopy(t, 0, o, 0, 16);
        car(o); car(o);
    }

    private static void inv(long[] o, long[] in) {
        long[] c = Arrays.copyOf(in, 16);
        for (int a = 253; a >= 0; a--) {
            mul(c, c, c);
            if (a != 2 && a != 4) mul(c, c, in);
        }
        System.arraycopy(c, 0, o, 0, 16);
    }

    /** X25519(scalar, point). */
    static byte[] x25519(byte[] scalar, byte[] point) {
        byte[] z = Arrays.copyOf(scalar, 32);
        z[31] = (byte) ((z[31] & 127) | 64);
        z[0] &= (byte) 248;
        long[] x = new long[16];
        for (int i = 0; i < 16; i++) x[i] = (point[2 * i] & 0xff) + ((long) (point[2 * i + 1] & 0xff) << 8);
        x[15] &= 0x7fff;
        long[] a = new long[16], b = Arrays.copyOf(x, 16), c = new long[16], d = new long[16], e = new long[16], f = new long[16];
        a[0] = d[0] = 1;
        for (int i = 254; i >= 0; --i) {
            int r = ((z[i >>> 3] & 0xff) >>> (i & 7)) & 1;
            sel(a, b, r); sel(c, d, r);
            add(e, a, c); sub(a, a, c); add(c, b, d); sub(b, b, d);
            mul(d, e, e); mul(f, a, a); mul(a, c, a); mul(c, b, e);
            add(e, a, c); sub(a, a, c); mul(b, a, a); sub(c, d, f);
            mul(a, c, A24); add(a, a, d); mul(c, c, a); mul(a, d, f);
            mul(d, b, x); mul(b, e, e);
            sel(a, b, r); sel(c, d, r);
        }
        inv(c, c);
        mul(a, a, c);
        byte[] out = new byte[32];
        pack(out, a);
        return out;
    }

    // ---- ChaCha20-Poly1305 ----

    private static int rotl(int v, int n) { return (v << n) | (v >>> (32 - n)); }

    private static int le32(byte[] b, int i) {
        return (b[i] & 0xff) | (b[i + 1] & 0xff) << 8 | (b[i + 2] & 0xff) << 16 | (b[i + 3] & 0xff) << 24;
    }

    private static void block(int[] st, byte[] out) {
        int[] x = st.clone();
        for (int i = 0; i < 10; i++) {
            quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13); quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
            quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12); quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) {
            int v = x[i] + st[i];
            out[4 * i] = (byte) v; out[4 * i + 1] = (byte) (v >>> 8); out[4 * i + 2] = (byte) (v >>> 16); out[4 * i + 3] = (byte) (v >>> 24);
        }
    }

    private static void quarter(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
    }

    private static int[] state(byte[] key, byte[] nonce, int counter) {
        int[] s = new int[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = le32(key, 4 * i);
        s[12] = counter;
        for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce, 4 * i);
        return s;
    }

    /** ChaCha20 XOR, starting at block counter. */
    static void chacha(byte[] key, byte[] nonce, int counter, byte[] in, int off, int len, byte[] out, int outOff) {
        int[] s = state(key, nonce, counter);
        byte[] ks = new byte[64];
        for (int done = 0; done < len; done += 64) {
            block(s, ks);
            s[12]++;
            for (int i = 0; i < Math.min(64, len - done); i++) out[outOff + done + i] = (byte) (in[off + done + i] ^ ks[i]);
        }
    }

    private static final BigInteger P1305 = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger CLAMP = new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);

    private static BigInteger leNum(byte[] b, int off, int len) {
        byte[] be = new byte[len + 1];
        for (int i = 0; i < len; i++) be[len - i] = b[off + i];
        return new BigInteger(be);
    }

    private static byte[] poly1305(byte[] otk, byte[] aad, byte[] ct, int ctOff, int ctLen) {
        BigInteger r = leNum(otk, 0, 16).and(CLAMP), s = leNum(otk, 16, 16), acc = BigInteger.ZERO;
        byte[] lens = new byte[16];
        for (int i = 0; i < 8; i++) {
            lens[i] = (byte) ((long) aad.length >>> (8 * i));
            lens[8 + i] = (byte) ((long) ctLen >>> (8 * i));
        }
        byte[][] parts = {aad, Arrays.copyOfRange(ct, ctOff, ctOff + ctLen), lens};
        for (byte[] p : parts) {
            for (int i = 0; i < p.length; i += 16) {
                byte[] blk = new byte[17];
                int n = Math.min(16, p.length - i);
                System.arraycopy(p, i, blk, 0, n);
                if (p != lens) n = 16; // the message and ad are padded to whole blocks
                blk[n] = 1;
                acc = acc.add(leNum(blk, 0, n + 1)).multiply(r).mod(P1305);
            }
        }
        byte[] be = acc.add(s).toByteArray(), tag = new byte[16];
        for (int i = 0; i < 16 && i < be.length; i++) tag[i] = be[be.length - 1 - i];
        return tag;
    }

    /** AEAD seal: ciphertext followed by the 16-byte tag. */
    static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plain) {
        byte[] otk = new byte[64];
        chacha(key, nonce, 0, new byte[64], 0, 64, otk, 0);
        byte[] out = new byte[plain.length + 16];
        chacha(key, nonce, 1, plain, 0, plain.length, out, 0);
        System.arraycopy(poly1305(otk, aad, out, 0, plain.length), 0, out, plain.length, 16);
        return out;
    }

    /** AEAD open, or null when the tag does not check out. */
    static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] sealed) {
        if (sealed.length < 16) return null;
        int n = sealed.length - 16;
        byte[] otk = new byte[64];
        chacha(key, nonce, 0, new byte[64], 0, 64, otk, 0);
        byte[] tag = poly1305(otk, aad, sealed, 0, n);
        if (!MessageDigest.isEqual(tag, Arrays.copyOfRange(sealed, n, sealed.length))) return null;
        byte[] out = new byte[n];
        chacha(key, nonce, 1, sealed, 0, n, out, 0);
        return out;
    }
}
