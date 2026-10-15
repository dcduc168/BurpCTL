package dev.burpctl.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.*;
import java.util.EnumSet;
import java.util.List;

public final class PrivateFiles {
    private static final boolean WINDOWS = System.getProperty("os.name").startsWith("Windows");
    private final long uid;
    private final UserPrincipal owner;
    private final List<AclEntry> acl;
    public PrivateFiles(Path root) throws IOException {
        uid = WINDOWS ? -1 : new com.sun.security.auth.module.UnixSystem().getUid();
        if (!WINDOWS) { owner = null; acl = List.of(); return; }
        owner = root.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
        acl = List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT).build());
    }
    public static Path runtimeRoot() throws IOException {
        if (WINDOWS) {
            String local = System.getenv("LOCALAPPDATA");
            if (local == null) throw new IOException("LOCALAPPDATA unavailable");
            return Path.of(local).toRealPath().resolve("burpctl");
        }
        // Keep GUI-launched Burp and shell-launched clients on the same short path.
        return Path.of("/tmp").toRealPath().resolve("burpctl-" + new com.sun.security.auth.module.UnixSystem().getUid());
    }
    private FileAttribute<?> attribute(boolean directory) {
        if (!WINDOWS) return PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
        return new FileAttribute<>() {
            public String name() { return "acl:acl"; }
            public List<AclEntry> value() { return acl; }
        };
    }
    public void newDirectory(Path path) throws IOException {
        Files.createDirectory(path, attribute(true));
        setCreatedOwner(path);
        check(path);
    }
    public void directory(Path path) throws IOException {
        try { Files.createDirectory(path, attribute(true)); setCreatedOwner(path); }
        catch (java.nio.file.FileAlreadyExistsException e) { /* Validate before reuse. */ }
        check(path);
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Invalid runtime directory");
    }
    public void file(Path path, String contents) throws IOException {
        Files.createFile(path, attribute(false));
        setCreatedOwner(path);
        check(path);
        Files.writeString(path, contents);
    }
    public void setCreatedOwner(Path path) throws IOException {
        if (!WINDOWS) return;
        // Elevated Windows tokens may default new objects to a group owner.
        var view = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) throw new IOException("Windows ACLs required");
        view.setOwner(owner);
    }
    public void socket(Path path) throws IOException {
        if (!WINDOWS) Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        setCreatedOwner(path);
        check(path, true);
    }
    public void check(Path path) throws IOException { check(path, false); }
    private void check(Path path, boolean socket) throws IOException {
        var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!WINDOWS) {
            int mode = (Integer)Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS);
            long pathUid = ((Number)Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue();
            int type = mode & 0170000;
            boolean validType = socket ? type == 0140000 : attrs.isDirectory() ||
                    (attrs.isRegularFile() && ((Number)Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() == 1);
            if (!validType || pathUid != uid || (mode & 07777) != (attrs.isDirectory() ? 0700 : 0600))
                throw new IOException("Runtime path is not private");
            return;
        }
        if (attrs.isSymbolicLink() || (!socket && attrs.isOther())) throw new IOException("Reparse point rejected");
        var view = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null || !view.getOwner().equals(owner)) throw new IOException("Unexpected runtime owner");
        var entries = view.getAcl();
        if (entries.isEmpty() || entries.stream().anyMatch(e -> e.type() != AclEntryType.ALLOW || !e.principal().equals(owner)))
            throw new IOException("Runtime ACL is not private");
    }
}
