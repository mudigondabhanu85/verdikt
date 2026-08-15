package com.verdikt.burp;

import java.util.List;
import java.util.Map;

/**
 * Minimal hand-rolled JSON writer — the extension has no other need for a
 * JSON library, so pulling in Gson/Jackson as a build dependency (and
 * having to shade it into the extension jar) isn't worth it for the one
 * small payload this extension ever sends.
 */
final class Json {
    private Json() {}

    static String object(Map<String, Object> fields) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            if (entry.getValue() == null) {
                continue;
            }
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append(string(entry.getKey())).append(":").append(value(entry.getValue()));
        }
        return sb.append("}").toString();
    }

    @SuppressWarnings("unchecked")
    private static String value(Object value) {
        if (value instanceof String) {
            return string((String) value);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof Map) {
            return object((Map<String, Object>) value);
        }
        if (value instanceof List) {
            StringBuilder sb = new StringBuilder("[");
            List<Object> list = (List<Object>) value;
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(value(list.get(i)));
            }
            return sb.append("]").toString();
        }
        return string(String.valueOf(value));
    }

    private static String string(String raw) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append("\"").toString();
    }
}
