package dev.burpctl.security;

import dev.burpctl.ipc.Fault;
import java.util.concurrent.atomic.AtomicBoolean;

public final class Policy {
    public final AtomicBoolean metadata = new AtomicBoolean();
    public final AtomicBoolean raw = new AtomicBoolean();
    public final AtomicBoolean screenshot = new AtomicBoolean();
    public void requireMetadata() { if (!metadata.get()) throw new Fault("PERMISSION_DENIED"); }
    public void requireRaw() { requireMetadata(); if (!raw.get()) throw new Fault("PERMISSION_DENIED"); }
    public void requireScreenshot() { if (!screenshot.get()) throw new Fault("PERMISSION_DENIED"); }
}
