import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.jar.JarFile;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/** Fixed loopback-only setup check using the JDK already present in the CE image. */
class CloudBeaverHealth {
    static boolean safePath(Path path) throws Exception {
        Path current = path.toAbsolutePath().getRoot();
        for (Path part : path.toAbsolutePath()) {
            current = current.resolve(part);
            BasicFileAttributes attributes;
            try { attributes = Files.readAttributes(current, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); }
            catch (NoSuchFileException absent) { return false; }
            if (attributes.isSymbolicLink() || (!current.equals(path.toAbsolutePath()) && !attributes.isDirectory()))
                throw new IllegalStateException();
        }
        return true;
    }

    static byte[] bounded(Path path, int limit) throws Exception {
        if (!safePath(path)) throw new IllegalStateException();
        var before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.size() > limit) throw new IllegalStateException();
        byte[] bytes;
        try (var stream = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = stream.readNBytes(limit+1);
        }
        var after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (bytes.length > limit || bytes.length != before.size() || !after.isRegularFile()
            || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
            || !Objects.equals(before.fileKey(), after.fileKey())) throw new IllegalStateException();
        return bytes;
    }

    static void driverConfiguration(Path workspace) throws Exception {
        driverConfiguration(workspace, false, true);
    }

    static void driverConfiguration(Path workspace, boolean postgresql, boolean mariadb) throws Exception {
        Path selected = workspace.resolve(".metadata/.config/drivers.xml");
        if (!safePath(selected)) selected = workspace.resolve(".metadata/.plugins/io.cloudbeaver.server.ce/drivers.xml");
        if (!safePath(selected)) return;
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        var builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler() {
            public void warning(SAXParseException error) throws SAXParseException { throw error; }
            public void error(SAXParseException error) throws SAXParseException { throw error; }
            public void fatalError(SAXParseException error) throws SAXParseException { throw error; }
        });
        var drivers = builder.parse(new ByteArrayInputStream(bounded(selected, 262144))).getElementsByTagNameNS("*", "driver");
        for (int index = 0; index < drivers.getLength(); index++) {
            Element driver = (Element) drivers.item(index);
            String provider = driver.getAttribute("provider");
            for (Node parent = driver.getParentNode(); parent instanceof Element; parent = parent.getParentNode()) {
                if ("provider".equals(parent.getLocalName())) {
                    provider = ((Element) parent).getAttribute("id");
                    break;
                }
            }
            if ((mariadb && provider.equals("mysql") && driver.getAttribute("id").equals("mariaDB"))
                || (postgresql && provider.equals("postgresql") && driver.getAttribute("id").equals("postgres-jdbc")))
                throw new IllegalStateException();
        }
    }

    static void cache(Path root, String digest) throws Exception {
        cache(root, Map.of("mariadb", digest));
    }

    static void cache(Path root, Map<String,String> digests) throws Exception {
        if (!safePath(root)) return;
        var pending = new ArrayDeque<Path>(); pending.add(root);
        int entries = 0; long bytes = 0;
        while (!pending.isEmpty()) {
            Path path = pending.removeFirst();
            if (++entries > 512 || root.relativize(path).getNameCount() > 8 || !safePath(path)) throw new IllegalStateException();
            var attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isDirectory()) {
                try (var children = Files.newDirectoryStream(path)) {
                    for (Path child : children) {
                        if (pending.size()+entries >= 512) throw new IllegalStateException();
                        pending.add(child);
                    }
                }
            } else if (path.getFileName().toString().endsWith(".jar")) {
                String name = path.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                for (var selected : digests.entrySet()) {
                    if (!name.contains(selected.getKey())) continue;
                    bytes += attributes.size();
                    if (bytes > 64*1024*1024 || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(bounded(path, 16*1024*1024))).equals(selected.getValue())) throw new IllegalStateException();
                }
            }
        }
    }

    static void driverHome(Path path, boolean properties) throws Exception {
        if (!safePath(path)) return;
        byte[] bytes = bounded(path, 262144);
        if (properties) {
            var values = new Properties(); values.load(new ByteArrayInputStream(bytes));
            if (values.containsKey("ui.drivers.home")) throw new IllegalStateException();
            return;
        }
        // Only recognize the reserved key, honoring JSON string escaping; never
        // interpret values or build a configuration/migration model.
        String text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        if (!text.strip().startsWith("{") || !text.strip().endsWith("}")) throw new IllegalStateException();
        for (int index=0; index<text.length(); index++) {
            if (text.charAt(index) != '"') continue;
            var decoded = new StringBuilder(); boolean closed = false;
            while (++index < text.length()) {
                char character = text.charAt(index);
                if (character == '"') { closed = true; break; }
                if (character < 32) throw new IllegalStateException();
                if (character == '\\') {
                    if (++index >= text.length()) throw new IllegalStateException();
                    character = text.charAt(index);
                    if (character == 'u') {
                        if (index+4 >= text.length() || !text.substring(index+1,index+5).matches("[0-9A-Fa-f]{4}")) throw new IllegalStateException();
                        decoded.append((char) Integer.parseInt(text.substring(index+1,index+5),16)); index+=4;
                    } else {
                        if ("\"\\/bfnrt".indexOf(character) < 0) throw new IllegalStateException();
                        decoded.append(switch (character) {
                            case 'b' -> '\b'; case 'f' -> '\f'; case 'n' -> '\n';
                            case 'r' -> '\r'; case 't' -> '\t'; default -> character;
                        });
                    }
                } else decoded.append(character);
            }
            if (!closed) throw new IllegalStateException();
            int next=index+1;
            while (next<text.length() && " \t\r\n".indexOf(text.charAt(next))>=0) next++;
            if (next<text.length() && text.charAt(next)==':' && decoded.toString().equals("ui.drivers.home")) throw new IllegalStateException();
        }
    }

    static void driverState(Path workspace, Path temporary, String digest, Map<String,String> environment) throws Exception {
        driverState(workspace, temporary, Map.of("mariadb", digest), environment);
    }

    static void driverState(Path workspace, Path temporary, Map<String,String> digests, Map<String,String> environment) throws Exception {
        // The generated server flags/configuration select the vendor default paths.
        if (!environment.getOrDefault("JAVA_OPTS", "").matches("-Xms128m -Xmx[0-9]{3,5}m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m")
            || !environment.getOrDefault("CLOUDBEAVER_DRIVERS_LOCATION", "drivers").equals("drivers")) throw new IllegalStateException();
        for (String key : new String[]{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}) {
            if (!environment.getOrDefault(key, "").isEmpty()) throw new IllegalStateException();
        }
        driverHome(workspace.resolve(".data/.cloudbeaver.runtime.conf"), false);
        driverHome(workspace.resolve(".data/.product.runtime.conf"), false);
        driverHome(workspace.resolve(".metadata/.plugins/org.eclipse.core.runtime/.settings/io.cloudbeaver.server.ce.prefs"), true);
        driverConfiguration(workspace, digests.containsKey("postgresql"), digests.containsKey("mariadb"));
        cache(workspace.resolve(".metadata/drivers"), digests);
        cache(workspace.resolve("data/libraries"), digests);
        cache(temporary.resolve("dbeaver/.work-data/data/libraries"), digests);
    }

    static String postgresqlDriver(Path directory) throws Exception {
        try (var entries = Files.list(directory)) {
            var jars = entries.filter(path -> path.getFileName().toString().matches("postgresql-.*\\.jar")).toList();
            if (jars.size() != 1) throw new IllegalStateException();
            Path jar = jars.get(0);
            var version = java.util.regex.Pattern.compile("postgresql-(42\\.7\\.([0-9]{1,3}))\\.jar")
                .matcher(jar.getFileName().toString());
            if (!version.matches() || Integer.parseInt(version.group(2)) < 13) throw new IllegalStateException();
            byte[] bytes = bounded(jar, 16*1024*1024);
            try (var archive = new JarFile(jar.toFile())) {
                if (archive.getManifest() == null || !version.group(1).equals(archive.getManifest().getMainAttributes()
                    .getValue("Implementation-Version"))) throw new IllegalStateException();
            }
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        }
    }

    static void driver(Path directory, String[] args, int offset) throws Exception {
        if (args.length == offset) return;
        if (args.length != offset + 3 || !args[offset].matches("3\\.5\\.[0-9]{1,3}")
            || Integer.parseInt(args[offset].split("\\.")[2]) < 11 || !args[offset+1].matches("[0-9a-f]{64}")
            || !(args[offset+2].equals("mariadb-java-client-"+args[offset]+".jar")
                || args[offset+2].equals("mariadb-java-client-3.5.10.jar"))) throw new IllegalArgumentException();
        try (var entries = Files.list(directory)) {
            var jars = entries.filter(path -> path.getFileName().toString().endsWith(".jar")).toList();
            if (jars.size() != 1 || !jars.get(0).getFileName().toString().equals(args[offset+2])) throw new IllegalStateException();
            Path jar = jars.get(0);
            if (!Files.isRegularFile(jar, LinkOption.NOFOLLOW_LINKS) || Files.size(jar) > 16*1024*1024
                || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)))
                    .equals(args[offset+1])) throw new IllegalStateException();
            try (var archive = new JarFile(jar.toFile())) {
                if (archive.getManifest() == null || !args[offset].equals(archive.getManifest().getMainAttributes()
                    .getValue("Bundle-Version"))) throw new IllegalStateException();
            }
        }
    }

    static boolean valid(String body) {
        String w = "[ \\t\\r\\n]*";
        String providers = "\\[" + w + "(?:\"local\"" + w + "," + w + "\"reverseProxy\"|\"reverseProxy\""
            + w + "," + w + "\"local\")" + w + "\\]";
        String pattern = "\\A" + w + "\\{" + w + "\"data\"" + w + ":" + w + "\\{" + w
            + "\"serverConfig\"" + w + ":" + w + "\\{" + w + "\"configurationMode\"" + w + ":" + w
            + "false" + w + "," + w + "\"anonymousAccessEnabled\"" + w + ":" + w + "false" + w + "," + w
            + "\"enabledAuthProviders\"" + w + ":" + w + providers + w + "," + w + "\"forceHttps\"" + w + ":" + w + "true" + w + "\\}" + w + "\\}" + w + "\\}" + w + "\\z";
        return body.matches(pattern);
    }
    public static void main(String[] args) {
        try {
            boolean configuration = args.length > 0 && args[0].equals("--configuration");
            int offset = configuration ? 1 : 0;
            boolean postgresql = args.length > offset && args[offset].equals("--postgresql");
            if (postgresql) offset++;
            driver(Path.of("/opt/cloudbeaver/drivers/mariadb"), args, offset);
            var digests = new java.util.HashMap<String,String>();
            if (postgresql) digests.put("postgresql", postgresqlDriver(Path.of("/opt/cloudbeaver/drivers/postgresql")));
            if (args.length != offset) digests.put("mariadb", args[offset+1]);
            if (!digests.isEmpty()) driverState(Path.of("/opt/cloudbeaver/workspace"),
                Path.of(System.getProperty("java.io.tmpdir")), digests, System.getenv());
            var connection = (HttpURLConnection) URI.create("http://127.0.0.1:8978/api/gql")
                .toURL().openConnection(Proxy.NO_PROXY);
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("X-Forwarded-Proto", "https");
            connection.setDoOutput(true);
            try (var output = connection.getOutputStream()) {
                output.write("{\"query\":\"{serverConfig{configurationMode anonymousAccessEnabled enabledAuthProviders forceHttps}}\"}"
                    .getBytes(StandardCharsets.UTF_8));
            }
            try (var stream = connection.getInputStream()) {
                byte[] bytes = stream.readNBytes(65537);
                String body = new String(bytes, StandardCharsets.UTF_8);
                if (connection.getResponseCode() != 200 || bytes.length > 65536 || !valid(body)) {
                    throw new IllegalStateException();
                }
                if (configuration) System.out.println(body);
            }
        } catch (Exception error) {
            System.err.println("CloudBeaver setup health refused");
            System.exit(1);
        }
    }
}
