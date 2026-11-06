import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Real loopback HTTP and pure negative cases, inside the pinned networkless image. */
class CloudBeaverHealthFixture {
    static volatile String scenario = "valid";
    static int stateControls = 0;
    static final String BODY = "{\"data\":{\"serverConfig\":{\"configurationMode\":false,\"anonymousAccessEnabled\":false,\"enabledAuthProviders\":[\"local\",\"reverseProxy\"],\"forceHttps\":true}}}";
    static void driverChecks() throws Exception {
        Path directory = Files.createTempDirectory("fixed-driver-");
        Path jar = directory.resolve("mariadb-java-client-3.5.10.jar");
        var manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Bundle-Version", "3.5.11");
        try (var archive = new JarOutputStream(Files.newOutputStream(jar), manifest)) { }
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)));
        CloudBeaverHealth.driver(directory, new String[]{"3.5.11", digest, jar.getFileName().toString()}, 0);
        CloudBeaverHealth.driver(directory, new String[]{"--configuration", "3.5.11", digest, jar.getFileName().toString()}, 1);
        for (String[] invalid : new String[][] {{"3.5.10",digest,jar.getFileName().toString()}, {"3.5.12",digest,jar.getFileName().toString()},
                {"3.5.11","0".repeat(64),jar.getFileName().toString()}, {"3.5.11",digest,"../driver.jar"}, {"3.5.11",digest}, {"invalid"}}) {
            refusesDriver(directory, invalid);
        }
        Files.copy(jar, directory.resolve("other.jar"));
        refusesDriver(directory, new String[]{"3.5.11",digest,jar.getFileName().toString()});
        Files.delete(directory.resolve("other.jar"));
        Path held = Files.move(jar, directory.resolve("saved.fixture"));
        Files.createSymbolicLink(jar, held);
        refusesDriver(directory, new String[]{"3.5.11",digest,jar.getFileName().toString()});
        Files.delete(jar); Files.delete(held); Files.delete(directory);
    }
    static void refusesDriver(Path directory, String[] fields) throws Exception {
        try { CloudBeaverHealth.driver(directory, fields, 0); }
        catch (Exception expected) { return; }
        throw new AssertionError("unsafe driver accepted");
    }
    static void pgJar(Path path, String version) throws Exception {
        var manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        if (version != null) manifest.getMainAttributes().putValue("Implementation-Version", version);
        try (var archive = new JarOutputStream(Files.newOutputStream(path), manifest)) { }
    }
    static void refusesPg(Path directory) throws Exception {
        try { CloudBeaverHealth.postgresqlDriver(directory); }
        catch (Exception expected) { stateControls++; return; }
        throw new AssertionError("unsupported PostgreSQL driver accepted");
    }
    static void postgresChecks() throws Exception {
        Path root = Files.createTempDirectory("pg-driver-state-");
        Path directory = root.resolve("packaged"), workspace = root.resolve("workspace"), temporary = root.resolve("temporary");
        Files.createDirectories(directory); Files.createDirectories(workspace); Files.createDirectories(temporary);
        refusesPg(directory);
        Path jar = directory.resolve("postgresql-42.7.13.jar"); pgJar(jar, "42.7.13");
        Files.writeString(directory.resolve("postgis-jdbc.jar"), "unrelated support jar");
        String digest = CloudBeaverHealth.postgresqlDriver(directory); stateControls++;
        if (!digest.equals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)))))
            throw new AssertionError("packaged PostgreSQL digest differs");
        Map<String,String> environment = Map.of("JAVA_OPTS", "-Xms128m -Xmx1024m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m");
        Map<String,String> hashes = Map.of("postgresql", digest);
        CloudBeaverHealth.driverState(workspace, temporary, hashes, environment); stateControls++;
        Path xml = workspace.resolve(".metadata/.config/drivers.xml"); Files.createDirectories(xml.getParent());
        Files.writeString(xml, "<drivers><provider id=\"mysql\"><driver id=\"mariaDB\"/></provider></drivers>");
        CloudBeaverHealth.driverState(workspace, temporary, hashes, environment); stateControls++;
        for (String text : new String[]{"<drivers><provider id=\"postgresql\"><driver id=\"postgres-jdbc\"/></provider></drivers>",
                "<drivers><driver provider=\"postgresql\" id=\"postgres-jdbc\"/></drivers>"}) {
            Files.writeString(xml, text);
            try { CloudBeaverHealth.driverState(workspace, temporary, hashes, environment); throw new AssertionError("PG override accepted"); }
            catch (IllegalStateException expected) { stateControls++; }
            if (!Files.readString(xml).equals(text)) throw new AssertionError("PG override modified");
        }
        Files.writeString(xml, "<drivers><provider id=\"postgresql\"><driver id=\"other\"/></provider></drivers>");
        CloudBeaverHealth.driverState(workspace, temporary, hashes, environment); stateControls++;
        for (Path cache : new Path[]{workspace.resolve(".metadata/drivers"), workspace.resolve("data/libraries"), temporary.resolve("dbeaver/.work-data/data/libraries")}) {
            Files.createDirectories(cache); Files.writeString(cache.resolve("mariadb.jar"), "unselected custom MariaDB jar");
            Path cached = cache.resolve("postgresql-42.7.13.jar"); Files.copy(jar, cached);
            CloudBeaverHealth.driverState(workspace, temporary, hashes, environment); stateControls++;
            Files.writeString(cached, "conflicting PostgreSQL jar");
            try { CloudBeaverHealth.driverState(workspace, temporary, hashes, environment); throw new AssertionError("PG cache accepted"); }
            catch (IllegalStateException expected) { stateControls++; }
            if (!Files.readString(cached).equals("conflicting PostgreSQL jar")) throw new AssertionError("PG cache modified");
            Files.delete(cached);
        }
        Files.copy(jar, directory.resolve("postgresql-42.7.14.jar")); refusesPg(directory); Files.delete(directory.resolve("postgresql-42.7.14.jar"));
        for (String version : new String[]{"42.7.12", "42.6.13", "43.7.13"}) {
            Files.delete(jar); Path other = directory.resolve("postgresql-"+version+".jar"); pgJar(other,version); refusesPg(directory); Files.delete(other);
            pgJar(jar,"42.7.13");
        }
        for (String version : new String[]{null,"42.7.12"}) { pgJar(jar,version); refusesPg(directory); }
        pgJar(jar,"42.7.13"); Path real = Files.move(jar, root.resolve("saved.jar")); Files.createSymbolicLink(jar,real); refusesPg(directory);
        Files.delete(jar); Files.move(real,jar);
        Files.delete(jar); jar=directory.resolve("postgresql-42.7.14.jar"); pgJar(jar,"42.7.14");
        CloudBeaverHealth.postgresqlDriver(directory); stateControls++;
        try (var paths=Files.walk(root)) { for (Path path:paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
    }
    static void stateChecks() throws Exception {
        Path root = Files.createTempDirectory("fixed-driver-state-");
        Path workspace = root.resolve("workspace"), temporary = root.resolve("temporary");
        Files.createDirectories(workspace); Files.createDirectories(temporary);
        Map<String,String> environment = Map.of("JAVA_OPTS", "-Xms128m -Xmx1024m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("selected bytes".getBytes(StandardCharsets.UTF_8)));
        acceptsState(workspace, temporary, hash, environment);
        for (String name : new String[]{".data/.cloudbeaver.runtime.conf", ".data/.product.runtime.conf"}) {
            Path file = workspace.resolve(name); Files.createDirectories(file.getParent());
            String harmless = "{\"server\":{\"productSettings\":{\"other\":\"quoted \\\"ui.drivers.home\\\": value\"}}}";
            Files.writeString(file, harmless); acceptsState(workspace, temporary, hash, environment);
            for (String text : new String[]{"{\"server\":{\"productSettings\":{\"ui.drivers.home\":\"drivers\"}}}",
                    "{\"ui.drivers.h\\u006fme\":\"custom\"}", "{\"unclosed}", "{\"invalid\\q\":0}"}) {
                Files.writeString(file, text); refusesState(workspace, temporary, hash, environment);
                if (!Files.readString(file).equals(text)) throw new AssertionError("runtime configuration changed");
            }
            Files.writeString(file, harmless);
        }
        Path preferences = workspace.resolve(".metadata/.plugins/org.eclipse.core.runtime/.settings/io.cloudbeaver.server.ce.prefs");
        Files.createDirectories(preferences.getParent()); Files.writeString(preferences, "other=value\n");
        acceptsState(workspace, temporary, hash, environment);
        for (String text : new String[]{"ui.drivers.home=drivers\n", "ui.drivers.h\\u006fme=custom\n"}) {
            Files.writeString(preferences, text); refusesState(workspace, temporary, hash, environment);
        }
        Files.writeString(preferences, "other=value\n");
        Path primary = workspace.resolve(".metadata/.config/drivers.xml"); Files.createDirectories(primary.getParent());
        Path legacy = workspace.resolve(".metadata/.plugins/io.cloudbeaver.server.ce/drivers.xml"); Files.createDirectories(legacy.getParent());
        String foreign = "<drivers><provider id=\"mysql\"><driver id=\"mariaDB\"/></provider></drivers>";
        String unrelated = "<drivers><provider id=\"postgresql\"><driver id=\"mariaDB\" provider=\"mysql\"/></provider><driver provider=\"mysql\" id=\"other\"/></drivers>";
        Files.writeString(legacy, foreign);
        refusesState(workspace, temporary, hash, environment);
        Files.writeString(primary, unrelated);
        acceptsState(workspace, temporary, hash, environment); // Effective primary wins over legacy.
        byte[] retained = Files.readAllBytes(primary);
        for (String xml : new String[]{foreign, "<drivers><driver provider=\"mysql\" id=\"mariaDB\"/></drivers>",
                "<drivers><driver", "<!DOCTYPE drivers [<!ENTITY private SYSTEM 'file:///SYNTHETIC_DONT_ECHO'>]><drivers>&private;</drivers>",
                " ".repeat(262145)}) {
            Files.writeString(primary, xml);
            refusesState(workspace, temporary, hash, environment);
            if (!Files.readString(primary).equals(xml)) throw new AssertionError("driver override was changed");
        }
        Files.write(primary, retained); acceptsState(workspace, temporary, hash, environment);
        Path real = root.resolve("actual.xml"); Files.move(primary, real); Files.createSymbolicLink(primary, real);
        refusesState(workspace, temporary, hash, environment); Files.delete(primary); Files.move(real, primary);
        for (Path cache : new Path[]{workspace.resolve(".metadata/drivers"), workspace.resolve("data/libraries"), temporary.resolve("dbeaver/.work-data/data/libraries")}) {
            Files.createDirectories(cache);
            Files.writeString(cache.resolve("postgresql.jar"), "unrelated custom bytes");
            Path jar = cache.resolve("mariadb-java-client-3.5.10.jar"); Files.writeString(jar, "selected bytes");
            acceptsState(workspace, temporary, hash, environment);
            Files.writeString(jar, "conflicting bytes"); refusesState(workspace, temporary, hash, environment);
            if (!Files.readString(jar).equals("conflicting bytes")) throw new AssertionError("cache was changed");
            Files.delete(jar); Files.createSymbolicLink(jar, cache.resolve("postgresql.jar"));
            refusesState(workspace, temporary, hash, environment); Files.delete(jar);
        }
        Path cache = workspace.resolve(".metadata/drivers");
        Path deep = cache;
        for (int n=0; n<9; n++) { deep = deep.resolve("deep"); Files.createDirectory(deep); }
        refusesState(workspace, temporary, hash, environment);
        try (var paths=Files.walk(cache)) { for (Path path:paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
        Files.createDirectory(cache);
        for (int n=0; n<512; n++) Files.writeString(cache.resolve("other-"+n), "");
        refusesState(workspace, temporary, hash, environment);
        for (String key : new String[]{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTS", "CLOUDBEAVER_DRIVERS_LOCATION"}) {
            var changed = new java.util.HashMap<>(environment); changed.put(key, "SYNTHETIC_OVERRIDE");
            // Use an empty workspace to isolate each runtime override refusal.
            refusesState(root.resolve("absent"), root.resolve("absent-tmp"), hash, changed);
        }
        refusesState(root.resolve("absent"), root.resolve("absent-tmp"), hash, Map.of());
        try (var paths=Files.walk(root)) { for (Path path:paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
    }
    static void acceptsState(Path workspace, Path temporary, String hash, Map<String,String> environment) throws Exception {
        CloudBeaverHealth.driverState(workspace, temporary, hash, environment); stateControls++;
    }
    static void refusesState(Path workspace, Path temporary, String hash, Map<String,String> environment) throws Exception {
        try { CloudBeaverHealth.driverState(workspace, temporary, hash, environment); }
        catch (Exception expected) { stateControls++; return; }
        throw new AssertionError("conflicting retained driver state accepted");
    }
    public static void main(String[] args) throws Exception {
        driverChecks();
        postgresChecks();
        stateChecks();
        if (!CloudBeaverHealth.valid(BODY) || !CloudBeaverHealth.valid(BODY.replace(",", ",\n "))
            || !CloudBeaverHealth.valid(BODY.replace("[\"local\",\"reverseProxy\"]", "[\"reverseProxy\",\"local\"]"))) {
            throw new AssertionError("valid configured response refused");
        }
        for (String invalid : new String[] {BODY.replace("\"forceHttps\":true", "\"forceHttps\":false"), BODY.replace("local", "loc al"), BODY.replace("false", "f alse"), "", "{}", "[]", BODY.replace("false", "true"),
            BODY.replace("\"anonymousAccessEnabled\":false", "\"anonymousAccessEnabled\":true"),
            BODY.replace("[\"local\",\"reverseProxy\"]", "[\"local\"]"),
            BODY.replace("[\"local\",\"reverseProxy\"]", "[\"local\",\"reverseProxy\",\"unknown\"]"),
            BODY.replace("{\"data\":", "{\"errors\":[\"not ready\"],\"data\":"),
            "{\"errors\":[\"\\\"configurationMode\\\":false,\\\"anonymousAccessEnabled\\\":false\"]}"}) {
            if (CloudBeaverHealth.valid(invalid)) throw new AssertionError("unsafe response accepted");
        }
        var executor = Executors.newFixedThreadPool(2);
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8978), 0);
        server.setExecutor(executor);
        server.createContext("/api/gql", exchange -> {
            String mode = scenario;
            String request = new String(exchange.getRequestBody().readNBytes(4096), StandardCharsets.UTF_8);
            if (!exchange.getRequestMethod().equals("POST") || !request.contains("serverConfig")
                || !"https".equals(exchange.getRequestHeaders().getFirst("X-Forwarded-Proto"))) {
                throw new AssertionError("wrong fixed request contract");
            }
            String body = switch (mode) {
                case "setup" -> BODY.replace("\"configurationMode\":false", "\"configurationMode\":true");
                case "anonymous" -> BODY.replace("\"anonymousAccessEnabled\":false", "\"anonymousAccessEnabled\":true");
                case "error" -> "{\"errors\":[\"SYNTHETIC_DONT_ECHO\"]}";
                case "oversized" -> " ".repeat(65537) + BODY;
                case "provider" -> BODY.replace("reverseProxy", "unknown");
                default -> BODY;
            };
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(mode.equals("redirect") ? 302 : 200, bytes.length);
            try (var output = exchange.getResponseBody()) {
                if (mode.equals("timeout")) {
                    try { Thread.sleep(4500); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                }
                output.write(bytes);
            }
        });
        server.start();
        try {
            for (String mode : new String[] {"valid", "setup", "anonymous", "error", "oversized", "provider", "redirect", "timeout", "invalid-argument"}) {
                scenario = mode;
                var process = new ProcessBuilder("/opt/java/openjdk/bin/java", "-Xms8m", "-Xmx64m", "-cp", args[0], "CloudBeaverHealth",
                    mode.equals("invalid-argument") ? "invalid" : "--configuration").start();
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    throw new AssertionError("bounded helper timed out");
                }
                String output = new String(process.getInputStream().readNBytes(65537), StandardCharsets.UTF_8);
                String error = new String(process.getErrorStream().readNBytes(65537), StandardCharsets.UTF_8);
                boolean success = mode.equals("valid");
                if ((process.exitValue() == 0) != success || (success && !CloudBeaverHealth.valid(output))
                    || (!success && !output.isEmpty()) || error.contains("SYNTHETIC_DONT_ECHO")) {
                    throw new AssertionError("incorrect safe HTTP result: " + mode);
                }
            }
        } finally {
            server.stop(0);
            executor.shutdownNow();
        }
        System.out.println("CloudBeaver setup health: "+(34+stateControls)+" controls passed");
    }
}
