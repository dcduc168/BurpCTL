package dev.burpctl.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.*;
import java.util.EnumSet;
import java.util.List;

public final class PrivateFiles {
    private final UserPrincipal owner;
    private final List<AclEntry> acl;
    public PrivateFiles(Path root) throws IOException {
        if (!System.getProperty("os.name").startsWith("Windows")) throw new IOException("Windows required");
        owner = root.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
        acl = List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT).build());
    }
    private FileAttribute<List<AclEntry>> attribute() {
        return new FileAttribute<>() {
            public String name() { return "acl:acl"; }
            public List<AclEntry> value() { return acl; }
        };
    }
    public void newDirectory(Path path) throws IOException {
        Files.createDirectory(path, attribute());
        check(path);
    }
    public void directory(Path path) throws IOException {
        try { Files.createDirectory(path, attribute()); }
        catch (java.nio.file.FileAlreadyExistsException e) { /* Validate before reuse. */ }
        check(path);
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Invalid runtime directory");
    }
    public void file(Path path, String contents) throws IOException {
        Files.createFile(path, attribute());
        check(path);
        Files.writeString(path, contents);
    }
    public void check(Path path) throws IOException {
        var attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attrs.isSymbolicLink() || attrs.isOther()) throw new IOException("Reparse point rejected");
        var view = Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null || !view.getOwner().equals(owner)) throw new IOException("Unexpected runtime owner");
        var entries = view.getAcl();
        if (entries.isEmpty() || entries.stream().anyMatch(e -> e.type() != AclEntryType.ALLOW || !e.principal().equals(owner)))
            throw new IOException("Runtime ACL is not private");
    }
}
