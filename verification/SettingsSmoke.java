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
        require(boxes.size() == 5, "Expected five permission controls");
        var metadata = boxes.get(0); var raw = boxes.get(1); var screenshot = boxes.get(2); var issues = boxes.get(3); var open = boxes.get(4);
        SwingUtilities.invokeAndWait(() -> {
            for (int width : new int[]{520, 320}) {
                panel.setSize(width, 700); layout(panel, false); layout(panel, false); layout(panel, true);
            }
            require(!metadata.isSelected() && !raw.isSelected() && !raw.isEnabled() && !screenshot.isSelected(), "Permissions must default off");
            require(!issues.isSelected() && !open.isSelected() && !open.isEnabled(), "New grants must default off");
            issues.doClick(0); require(policy.issues.get() && !policy.metadata.get(), "Issues grant independent");
            screenshot.doClick(0);
            require(policy.screenshot.get() && !policy.metadata.get() && !policy.raw.get(), "Screenshot permission independent of history");
            require(metadata.getMnemonic() != 0 && raw.getMnemonic() != 0 && metadata.getMnemonic() != raw.getMnemonic(), "Keyboard access");
            require(raw.getAccessibleContext().getAccessibleDescription().contains("metadata"), "Missing dependency description");
            metadata.doClick(0);
            require(policy.metadata.get() && !policy.raw.get() && raw.isEnabled(), "Metadata-only grant");
            raw.doClick(0); require(policy.metadata.get() && policy.raw.get() && open.isEnabled(), "Raw grant");
            open.doClick(0); require(policy.repeaterOpen.get(), "Explicit Repeater UI grant");
            metadata.doClick(0);
            require(!policy.metadata.get() && !policy.raw.get() && !raw.isSelected() && !raw.isEnabled(), "Metadata revoke must revoke raw");
            require(!policy.repeaterOpen.get() && !open.isSelected() && !open.isEnabled(), "Raw revoke must revoke UI write");
            metadata.doClick(0); require(!policy.raw.get(), "Raw permission silently restored");
            raw.doClick(0);
        });
        settings.close();
        require(!policy.metadata.get() && !policy.raw.get() && !policy.screenshot.get() && !policy.issues.get() && !policy.repeaterOpen.get(), "Unload did not revoke immediately");
        SwingUtilities.invokeAndWait(() -> {
            require(!metadata.isEnabled() && !raw.isEnabled() && !screenshot.isEnabled(), "Unloaded UI remains enabled");
            for (var box : boxes) {
                box.setSelected(true);
                for (var listener : box.getActionListeners()) listener.actionPerformed(new java.awt.event.ActionEvent(box, 0, "stale"));
            }
            require(!policy.metadata.get() && !policy.raw.get() && !policy.screenshot.get() && !policy.issues.get() && !policy.repeaterOpen.get() && boxes.stream().noneMatch(JCheckBox::isSelected), "Stale UI regranted permissions");
        });
        var late = new PermissionSettings(ui, new Policy()); late.close();
        var lateBoxes = new ArrayList<JCheckBox>(); collect(late.uiComponent(), lateBoxes);
        require(lateBoxes.stream().noneMatch(JCheckBox::isEnabled), "UI created after unload is active");
        late.close();
        System.out.println("PASS: lazy/single EDT panel, search/accessibility, permission dependency, unload/stale UI revocation");
    }
}
