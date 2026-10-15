package dev.burpctl;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import dev.burpctl.runtime.Server;
import dev.burpctl.security.Policy;
import dev.burpctl.ui.PermissionSettings;
import javax.swing.*;

public final class BurpCtlExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BurpCTL");
        var policy = new Policy();
        var server = new Server(api, policy);
        var settings = new PermissionSettings(api.userInterface(), policy);
        var settingsRegistration = new java.util.concurrent.atomic.AtomicReference<burp.api.montoya.core.Registration>();
        var stopped = new java.util.concurrent.atomic.AtomicBoolean();
        api.extension().registerUnloadingHandler(() -> {
            stopped.set(true); settings.close(); server.close();
            var registration = settingsRegistration.getAndSet(null);
            if (registration != null) registration.deregister();
        });
        SwingUtilities.invokeLater(() -> {
            if (stopped.get()) return;
            var registration = api.userInterface().registerSettingsPanel(settings);
            settingsRegistration.set(registration);
            if (stopped.get() && settingsRegistration.compareAndSet(registration, null)) registration.deregister();
        });
        var startup = new Thread(() -> {
            try {
                server.start();
                if (!stopped.get()) api.logging().logToOutput("BurpCTL ready (" + Server.EXTENSION_VERSION + ").");
            } catch (Exception e) {
                server.close();
                if (!stopped.get()) api.logging().logToError("BurpCTL startup failed: " + e.getClass().getSimpleName() + "; check runtime path and private filesystem permissions.");
            }
        }, "burpctl-start");
        startup.setDaemon(true); startup.start();
    }
}
