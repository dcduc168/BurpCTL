package dev.burpctl.ipc;

public final class Fault extends RuntimeException {
    public final String code;
    public Fault(String code) { this(code, code.replace('_', ' ').toLowerCase(java.util.Locale.ROOT)); }
    public Fault(String code, String message) { super(message, null, false, false); this.code = code; }
}
