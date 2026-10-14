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
    private JLabel state;
    private boolean closed;

    public PermissionSettings(UserInterface ui, Policy policy) { this.ui = ui; this.policy = policy; }

    @Override public Set<String> keywords() { return Set.of("BurpCTL", "CLI", "history", "permissions", "metadata", "raw", "body"); }

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
        content.add(text("Choose which in-scope history data local CLI tools may read."));
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
        content.add(Box.createVerticalStrut(20));
        state = new JLabel();
        content.add(state);
        content.add(Box.createVerticalStrut(8));
        content.add(text("Changes apply immediately. Permissions reset when the extension reloads."));
        content.add(Box.createVerticalStrut(8));
        content.add(text("Status and scope checks remain available. Scope membership is not engagement authorization."));
        metadata.addActionListener(event -> update());
        raw.addActionListener(event -> update());
        var row = new GridBagConstraints();
        row.gridx = 0; row.gridy = GridBagConstraints.RELATIVE;
        row.weightx = 1; row.fill = GridBagConstraints.HORIZONTAL; row.anchor = GridBagConstraints.WEST;
        for (var child : content.getComponents()) layout.setConstraints(child, row);
        panel.add(content, BorderLayout.NORTH);
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
        refresh();
    }

    private synchronized void refresh() {
        if (panel == null) return;
        metadata.setSelected(!closed && policy.metadata.get());
        raw.setSelected(!closed && policy.metadata.get() && policy.raw.get());
        metadata.setEnabled(!closed);
        raw.setEnabled(!closed && metadata.isSelected());
        state.setText(closed ? "Extension unloaded"
                : !metadata.isSelected() ? "History reads disabled"
                : raw.isSelected() ? "Metadata and raw reads enabled" : "Metadata reads enabled");
    }

    @Override public synchronized void close() {
        closed = true; policy.metadata.set(false); policy.raw.set(false);
        if (panel != null) SwingUtilities.invokeLater(this::refresh);
    }
}
