package dev.burpctl.ipc;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Json {
    private static final Gson GSON = new GsonBuilder().serializeNulls().create();
    private Json() {}
    public static String encode(Object value) { return new String(bytes(value, Frames.MAX_PAYLOAD), java.nio.charset.StandardCharsets.UTF_8); }
    public static byte[] bytes(Object value, int maximum) {
        var output = new java.io.ByteArrayOutputStream() {
            @Override public synchronized void write(byte[] bytes, int offset, int length) {
                if (length > maximum - count) throw new Fault("OUTPUT_LIMIT");
                super.write(bytes, offset, length);
            }
            @Override public synchronized void write(int value) {
                if (count >= maximum) throw new Fault("OUTPUT_LIMIT");
                super.write(value);
            }
        };
        var encoder = java.nio.charset.StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
        try (var writer = new java.io.OutputStreamWriter(output, encoder)) {
            GSON.toJson(value, writer);
        } catch (IOException e) { throw new Fault("INTERNAL_ERROR"); }
        return output.toByteArray();
    }
    public static Map<String, Object> decode(String value) throws IOException {
        try (var reader = new JsonReader(new StringReader(value))) {
            reader.setStrictness(Strictness.STRICT);
            Object result = read(reader, 0);
            if (!(result instanceof Map<?, ?>) || reader.peek() != JsonToken.END_DOCUMENT)
                throw new IOException("Expected one JSON object");
            @SuppressWarnings("unchecked") var object = (Map<String, Object>) result;
            return object;
        } catch (RuntimeException e) { throw new IOException("Invalid JSON"); }
    }
    private static Object read(JsonReader reader, int depth) throws IOException {
        if (depth > 16) throw new IOException("JSON too deep");
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                var result = new LinkedHashMap<String, Object>();
                reader.beginObject();
                while (reader.hasNext()) {
                    String key = unicode(reader.nextName());
                    if (result.containsKey(key) || result.size() >= 1024) throw new IOException("Invalid keys");
                    result.put(key, read(reader, depth + 1));
                }
                reader.endObject(); yield result;
            }
            case BEGIN_ARRAY -> {
                var result = new ArrayList<Object>();
                reader.beginArray();
                while (reader.hasNext()) {
                    if (result.size() >= 1024) throw new IOException("Array too long");
                    result.add(read(reader, depth + 1));
                }
                reader.endArray(); yield result;
            }
            case STRING -> unicode(reader.nextString());
            case NUMBER -> Long.parseLong(reader.nextString());
            case BOOLEAN -> reader.nextBoolean();
            case NULL -> { reader.nextNull(); yield null; }
            default -> throw new IOException("Invalid JSON token");
        };
    }
    private static String unicode(String value) throws IOException {
        for (int i = 0; i < value.length(); i++) {
            char unit = value.charAt(i);
            if (Character.isHighSurrogate(unit)) {
                if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw new IOException("Invalid Unicode");
            } else if (Character.isLowSurrogate(unit)) throw new IOException("Invalid Unicode");
        }
        return value;
    }
}
