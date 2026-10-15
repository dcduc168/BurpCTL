package dev.burpctl.ui;

import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.settings.SettingsPanel;
import dev.burpctl.security.Policy;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Font;
import java.util.Set;
import javax.swing.*;

public final class PermissionSettings implements SettingsPanel, AutoCloseable {
    private final UserInterface ui;
    private final Policy policy;
    private JPanel panel;
    private JCheckBox metadata;
    private JCheckBox raw;
    private JCheckBox screenshot;
    private JCheckBox issues;
    private JCheckBox repeaterOpen;
    private JLabel state;
    private boolean closed;

    public PermissionSettings(UserInterface ui, Policy policy) { this.ui = ui; this.policy = policy; }

    @Override public Set<String> keywords() { return Set.of("BurpCTL", "CLI", "history", "permissions", "metadata", "raw", "body", "Repeater", "screenshot", "issues", "findings"); }

    @Override public JComponent uiComponent() {
        if (SwingUtilities.isEventDispatchThread()) return component();
        try { SwingUtilities.invokeAndWait(this::component); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("Settings UI interrupted", e); }
        catch (java.lang.reflect.InvocationTargetException e) { throw new IllegalStateException("Settings UI unavailable", e.getCause()); }
        return panel;
    }

    private synchronized JPanel component() {
        if (panel != null) return panel;
        panel = new JPanel(new BorderLayout());
        var layout = new GridBagLayout();
        var content = new JPanel(layout);
        content.setBorder(BorderFactory.createEmptyBorder(20, 24, 24, 24));
        var title = new JLabel("CLI permissions");
        content.add(title);
        content.add(Box.createVerticalStrut(8));
        content.add(text("Choose which data local CLI tools may read and whether they may open Repeater tabs."));
        content.add(Box.createVerticalStrut(20));
        metadata = new JCheckBox("Allow history metadata");
        metadata.setMnemonic('M');
        metadata.getAccessibleContext().setAccessibleDescription("Allow methods, hosts, paths and response status for in-scope history.");
        content.add(metadata);
        var metadataHint = text("Methods, hosts, paths and response status.");
        content.add(metadataHint);
        content.add(Box.createVerticalStrut(16));
        raw = new JCheckBox("Allow message and body reads");
        raw.setMnemonic('R');
        raw.getAccessibleContext().setAccessibleDescription("Allow full HTTP messages, headers and body bytes. Enable metadata access first.");
        content.add(raw);
        var rawHint = text("Full HTTP messages, headers and body bytes. Requires metadata access.");
        content.add(rawHint);
        content.add(Box.createVerticalStrut(16));
        screenshot = new JCheckBox("Allow Repeater screenshots");
        screenshot.setMnemonic('S');
        screenshot.getAccessibleContext().setAccessibleDescription("Allow PNG captures of the Repeater pane, even while another main tool is selected, including sensitive data outside target scope.");
        content.add(screenshot);
        content.add(text("Repeater content, even while another tool is selected. May include headers, bodies and data outside scope. Independent of history permissions."));
        content.add(Box.createVerticalStrut(16));
        issues = new JCheckBox("Allow scanner issue reads");
        issues.setMnemonic('I');
        issues.getAccessibleContext().setAccessibleDescription("Allow in-scope scanner findings, including potentially sensitive details. Independent of history permissions.");
        content.add(issues);
        content.add(text("In-scope findings and their details. Does not start scans or read attached HTTP messages. Requires Professional."));
        content.add(Box.createVerticalStrut(16));
        repeaterOpen = new JCheckBox("Allow opening Repeater tabs");
        repeaterOpen.setMnemonic('O');
        repeaterOpen.getAccessibleContext().setAccessibleDescription("Allow copying an in-scope history request into a new Repeater tab. Requires metadata and raw access. Does not send requests.");
        content.add(repeaterOpen);
        content.add(text("Copy a history request into Repeater without sending it. Requires metadata and raw access."));
        content.add(Box.createVerticalStrut(20));
        state = new JLabel();
        content.add(state);
        content.add(Box.createVerticalStrut(8));
        content.add(text("Changes apply immediately. Permissions reset when the extension reloads."));
        content.add(Box.createVerticalStrut(8));
        content.add(text("Status and scope checks remain available. Scope membership is not engagement authorization."));
        metadata.addActionListener(event -> update());
        raw.addActionListener(event -> update());
        screenshot.addActionListener(event -> update());
        issues.addActionListener(event -> update());
        repeaterOpen.addActionListener(event -> update());
        var row = new GridBagConstraints();
        row.gridx = 0; row.gridy = GridBagConstraints.RELATIVE;
        row.weightx = 1; row.fill = GridBagConstraints.HORIZONTAL; row.anchor = GridBagConstraints.WEST;
        for (var child : content.getComponents()) layout.setConstraints(child, row);
        var scroll = new JScrollPane(content, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        panel.add(scroll, BorderLayout.CENTER);
        ui.applyThemeToComponent(panel);
        for (var child : content.getComponents()) if (child instanceof JTextArea text) text.setFont(title.getFont().deriveFont(Font.PLAIN));
        int hintIndent = metadata.getPreferredSize().height;
        metadataHint.setBorder(BorderFactory.createEmptyBorder(0, hintIndent, 0, 0));
        rawHint.setBorder(BorderFactory.createEmptyBorder(0, hintIndent, 0, 0));
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 4));
        refresh();
        return panel;
    }

    private static JTextArea text(String value) {
        var text = new JTextArea(value) {
            @Override public Dimension getPreferredSize() {
                if (getParent() == null) return super.getPreferredSize();
                var parentInsets = getParent().getInsets();
                int width = getParent().getWidth() - parentInsets.left - parentInsets.right;
                if (width <= 0) return super.getPreferredSize();
                var insets = getInsets();
                var view = getUI().getRootView(this);
                view.setSize(Math.max(1, width - insets.left - insets.right), Integer.MAX_VALUE);
                return new Dimension(width, (int)Math.ceil(view.getPreferredSpan(javax.swing.text.View.Y_AXIS)) + insets.top + insets.bottom);
            }
        };
        text.setEditable(false); text.setFocusable(false); text.setOpaque(false);
        text.setLineWrap(true); text.setWrapStyleWord(true);
        text.setBorder(BorderFactory.createEmptyBorder());
        return text;
    }

    private synchronized void update() {
        if (closed) { refresh(); return; }
        if (!metadata.isSelected()) { raw.setSelected(false); policy.raw.set(false); }
        policy.metadata.set(metadata.isSelected());
        policy.raw.set(raw.isSelected());
        policy.screenshot.set(screenshot.isSelected());
        policy.issues.set(issues.isSelected());
        if (!raw.isSelected()) repeaterOpen.setSelected(false);
        policy.repeaterOpen.set(repeaterOpen.isSelected());
        refresh();
    }

    private synchronized void refresh() {
        if (panel == null) return;
        metadata.setSelected(!closed && policy.metadata.get());
        raw.setSelected(!closed && policy.metadata.get() && policy.raw.get());
        metadata.setEnabled(!closed);
        raw.setEnabled(!closed && metadata.isSelected());
        screenshot.setSelected(!closed && policy.screenshot.get());
        screenshot.setEnabled(!closed);
        issues.setSelected(!closed && policy.issues.get());
        issues.setEnabled(!closed);
        repeaterOpen.setSelected(!closed && policy.metadata.get() && policy.raw.get() && policy.repeaterOpen.get());
        repeaterOpen.setEnabled(!closed && raw.isSelected());
        int enabled = (metadata.isSelected() ? 1 : 0) + (raw.isSelected() ? 1 : 0) + (screenshot.isSelected() ? 1 : 0)
                + (issues.isSelected() ? 1 : 0) + (repeaterOpen.isSelected() ? 1 : 0);
        state.setText(closed ? "Extension unloaded" : enabled == 0 ? "CLI permissions disabled" : "Enabled permissions: " + enabled);
    }

    @Override public synchronized void close() {
        closed = true; policy.metadata.set(false); policy.raw.set(false); policy.screenshot.set(false); policy.issues.set(false); policy.repeaterOpen.set(false);
        if (panel != null) SwingUtilities.invokeLater(this::refresh);
    }
}
