import burp.api.montoya.ui.UserInterface;
import dev.burpctl.security.Policy;
import dev.burpctl.ui.PermissionSettings;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;

/** Settings dependency, permission revocation and lazy UI checks; no Burp traffic. */
public final class SettingsSmoke {
    static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    static void collect(Component component, List<JCheckBox> boxes) {
        if (component instanceof JCheckBox box) boxes.add(box);
        if (component instanceof Container container) for (var child : container.getComponents()) collect(child, boxes);
    }
    static void layout(Component component, boolean checkText) {
        if (checkText && component instanceof JTextArea text)
            require(text.getHeight() >= text.getPreferredSize().height, "Wrapped help text clipped");
        if (component instanceof Container container) {
            if (!checkText) container.doLayout();
            for (var child : container.getComponents()) layout(child, checkText);
        }
    }
    public static void main(String[] args) throws Exception {
        var themes = new AtomicInteger();
        var ui = HistorySmoke.proxy(UserInterface.class, (method, values) -> {
            if (!method.equals("applyThemeToComponent")) throw new AssertionError(method);
            require(SwingUtilities.isEventDispatchThread(), "Theme applied off EDT");
            themes.incrementAndGet(); return null;
        });
        var policy = new Policy();
        var settings = new PermissionSettings(ui, policy);
        require(themes.get() == 0, "Settings constructed UI eagerly");
        require(settings.keywords().containsAll(List.of("BurpCTL", "CLI", "permissions")), "Missing search terms");
        var panel = settings.uiComponent();
        require(settings.uiComponent() == panel && themes.get() == 1, "Repeated open rebuilt UI");
        var boxes = new ArrayList<JCheckBox>(); collect(panel, boxes);
        require(boxes.size() == 2, "Expected two permission controls");
        var metadata = boxes.get(0); var raw = boxes.get(1);
        SwingUtilities.invokeAndWait(() -> {
            for (int width : new int[]{520, 320}) {
                panel.setSize(width, 700); layout(panel, false); layout(panel, false); layout(panel, true);
            }
            require(!metadata.isSelected() && !raw.isSelected() && !raw.isEnabled(), "Permissions must default off");
            require(metadata.getMnemonic() != 0 && raw.getMnemonic() != 0 && metadata.getMnemonic() != raw.getMnemonic(), "Keyboard access");
            require(raw.getAccessibleContext().getAccessibleDescription().contains("metadata"), "Missing dependency description");
            metadata.doClick(0);
            require(policy.metadata.get() && !policy.raw.get() && raw.isEnabled(), "Metadata-only grant");
            raw.doClick(0); require(policy.metadata.get() && policy.raw.get(), "Raw grant");
            metadata.doClick(0);
            require(!policy.metadata.get() && !policy.raw.get() && !raw.isSelected() && !raw.isEnabled(), "Metadata revoke must revoke raw");
            metadata.doClick(0); require(!policy.raw.get(), "Raw permission silently restored");
            raw.doClick(0);
        });
        settings.close();
        require(!policy.metadata.get() && !policy.raw.get(), "Unload did not revoke immediately");
        SwingUtilities.invokeAndWait(() -> {
            require(!metadata.isEnabled() && !raw.isEnabled(), "Unloaded UI remains enabled");
            metadata.setSelected(true);
            for (var listener : metadata.getActionListeners()) listener.actionPerformed(new java.awt.event.ActionEvent(metadata, 0, "stale"));
            require(!policy.metadata.get() && !policy.raw.get() && !metadata.isSelected(), "Stale UI regranted permissions");
        });
        var late = new PermissionSettings(ui, new Policy()); late.close();
        var lateBoxes = new ArrayList<JCheckBox>(); collect(late.uiComponent(), lateBoxes);
        require(lateBoxes.stream().noneMatch(JCheckBox::isEnabled), "UI created after unload is active");
        late.close();
        System.out.println("PASS: lazy/single EDT panel, search/accessibility, permission dependency, unload/stale UI revocation");
    }
}
