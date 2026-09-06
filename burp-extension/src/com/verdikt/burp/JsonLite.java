package com.verdikt.burp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal hand-rolled JSON reader — the counterpart to {@link Json}'s
 * writer. Only used to pull a handful of string fields (id/name) out of
 * Verdikt API responses for the settings panel's project/version
 * dropdowns, so this deliberately doesn't aim to be a general-purpose
 * JSON library: every scalar value is read and exposed as its string
 * form (good enough for UUIDs, names, and simple text fields), nested
 * objects/arrays are parsed structurally but not specially typed.
 */
final class JsonLite {
    private JsonLite() {}

    /** Parses a top-level JSON array of flat objects into a list of
     * String-valued maps — e.g. Verdikt's {@code GET /projects} response
     * shape ({@code [{"id": "...", "name": "...", ...}, ...]}). */
    static List<Map<String, String>> parseObjectArray(String json) {
        Parser parser = new Parser(json);
        Object value = parser.parseValue();
        List<Map<String, String>> result = new ArrayList<>();
        if (value instanceof List) {
            for (Object item : (List<?>) value) {
                if (item instanceof Map) {
                    result.add(flatten((Map<?, ?>) item));
                }
            }
        }
        return result;
    }

    /** Parses a single top-level JSON object into a String-valued map. */
    static Map<String, String> parseObject(String json) {
        Parser parser = new Parser(json);
        Object value = parser.parseValue();
        if (value instanceof Map) {
            return flatten((Map<?, ?>) value);
        }
        return new LinkedHashMap<>();
    }

    private static Map<String, String> flatten(Map<?, ?> raw) {
        Map<String, String> flat = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            Object v = entry.getValue();
            flat.put(String.valueOf(entry.getKey()), v == null ? null : String.valueOf(v));
        }
        return flat;
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
            this.i = 0;
        }

        Object parseValue() {
            skipWhitespace();
            if (i >= s.length()) {
                return null;
            }
            char c = s.charAt(i);
            if (c == '{') {
                return parseObjectValue();
            }
            if (c == '[') {
                return parseArrayValue();
            }
            if (c == '"') {
                return parseString();
            }
            if (s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            if (s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            return parseNumber();
        }

        private Map<String, Object> parseObjectValue() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') {
                i++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                char next = peek();
                if (next == ',') {
                    i++;
                    continue;
                }
                if (next == '}') {
                    i++;
                    break;
                }
                throw new IllegalStateException("Malformed JSON object at index " + i);
            }
            return map;
        }

        private List<Object> parseArrayValue() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek() == ']') {
                i++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                char next = peek();
                if (next == ',') {
                    i++;
                    continue;
                }
                if (next == ']') {
                    i++;
                    break;
                }
                throw new IllegalStateException("Malformed JSON array at index " + i);
            }
            return list;
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char escaped = s.charAt(i++);
                    switch (escaped) {
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default:
                            sb.append(escaped);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Double parseNumber() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            return Double.parseDouble(s.substring(start, i));
        }

        private void skipWhitespace() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        private char peek() {
            return i < s.length() ? s.charAt(i) : '\0';
        }

        private void expect(char c) {
            skipWhitespace();
            if (i >= s.length() || s.charAt(i) != c) {
                throw new IllegalStateException("Expected '" + c + "' at index " + i);
            }
            i++;
        }
    }
}
