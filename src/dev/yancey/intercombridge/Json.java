package dev.yancey.intercombridge;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small JSON: objects are Maps, arrays Lists, numbers Doubles or Longs. */
final class Json {
    private Json() {}

    static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String) {
            quote(b, (String) v);
        } else if (v instanceof Boolean || v instanceof Integer || v instanceof Long) {
            b.append(v);
        } else if (v instanceof Number) {
            double d = ((Number) v).doubleValue();
            if (d == Math.rint(d) && Math.abs(d) < 1e15) b.append((long) d); else b.append(d);
        } else if (v instanceof Map) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) b.append(',');
                first = false;
                quote(b, String.valueOf(e.getKey()));
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof Collection) {
            b.append('[');
            boolean first = true;
            for (Object o : (Collection<?>) v) {
                if (!first) b.append(',');
                first = false;
                write(b, o);
            }
            b.append(']');
        } else {
            quote(b, v.toString());
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        b.append('"');
    }

    static Object parse(byte[] utf8) throws IOException {
        return parse(new String(utf8, StandardCharsets.UTF_8));
    }

    static Object parse(String s) throws IOException {
        Json.Parser p = new Json.Parser(s);
        Object v = p.value();
        p.space();
        if (p.i != s.length()) throw new IOException("JSON: trailing data");
        return v;
    }

    /** The object parsed from b, or an empty map when it is not one. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> object(byte[] b) {
        try {
            Object v = parse(b);
            return v instanceof Map ? (Map<String, Object>) v : new LinkedHashMap<String, Object>();
        } catch (IOException e) {
            return new LinkedHashMap<>();
        }
    }

    static String str(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof String ? (String) v : "";
    }

    static boolean bool(Map<String, Object> m, String k) {
        return Boolean.TRUE.equals(m.get(k));
    }

    static long num(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Number ? ((Number) v).longValue() : 0;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Map ? (Map<String, Object>) v : new LinkedHashMap<String, Object>();
    }

    private static final class Parser {
        final String s;
        int i;

        Parser(String s) { this.s = s; }

        void space() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        IOException bad() { return new IOException("JSON: unexpected input at " + i); }

        Object value() throws IOException {
            space();
            if (i >= s.length()) throw bad();
            char c = s.charAt(i);
            if (c == '{') {
                i++;
                Map<String, Object> m = new LinkedHashMap<>();
                space();
                if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
                while (true) {
                    space();
                    if (i >= s.length() || s.charAt(i) != '"') throw bad();
                    String k = string();
                    space();
                    if (i >= s.length() || s.charAt(i++) != ':') throw bad();
                    m.put(k, value());
                    space();
                    if (i >= s.length()) throw bad();
                    char d = s.charAt(i++);
                    if (d == '}') return m;
                    if (d != ',') throw bad();
                }
            }
            if (c == '[') {
                i++;
                List<Object> l = new ArrayList<>();
                space();
                if (i < s.length() && s.charAt(i) == ']') { i++; return l; }
                while (true) {
                    l.add(value());
                    space();
                    if (i >= s.length()) throw bad();
                    char d = s.charAt(i++);
                    if (d == ']') return l;
                    if (d != ',') throw bad();
                }
            }
            if (c == '"') return string();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            if (start == i) throw bad();
            String n = s.substring(start, i);
            try {
                if (n.matches("-?\\d{1,18}")) return Long.parseLong(n);
                return Double.parseDouble(n);
            } catch (NumberFormatException e) {
                throw bad();
            }
        }

        String string() throws IOException {
            i++; // the opening quote
            StringBuilder b = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                if (i >= s.length()) throw bad();
                char e = s.charAt(i++);
                switch (e) {
                    case 'n': b.append('\n'); break;
                    case 't': b.append('\t'); break;
                    case 'r': b.append('\r'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'u':
                        if (i + 4 > s.length()) throw bad();
                        try {
                            b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        } catch (NumberFormatException x) {
                            throw bad();
                        }
                        i += 4;
                        break;
                    default: b.append(e);
                }
            }
            throw bad();
        }
    }
}
