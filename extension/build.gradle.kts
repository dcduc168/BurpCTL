plugins { java }
group = "dev.burpctl"
version = "0.1.0"
repositories { mavenCentral() }
dependencies { compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7"); implementation("com.google.code.gson:gson:2.13.2") }
dependencyLocking { lockAllConfigurations() }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
tasks.withType<JavaCompile>().configureEach { options.release.set(21) }
tasks.jar {
    manifest { attributes["Implementation-Version"] = project.version.toString() }
    archiveFileName.set("burpctl-extension.jar")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    exclude("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "module-info.class")
}
