import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Real loopback HTTP and pure negative cases, inside the pinned networkless image. */
class CloudBeaverHealthFixture {
    static volatile String scenario = "valid";
    static final String BODY = "{\"data\":{\"serverConfig\":{\"configurationMode\":false,\"anonymousAccessEnabled\":false,\"enabledAuthProviders\":[\"local\",\"reverseProxy\"],\"forceHttps\":true}}}";
    public static void main(String[] args) throws Exception {
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
                var process = new ProcessBuilder("java", "-Xms8m", "-Xmx64m", "-cp", args[0], "CloudBeaverHealth",
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
        System.out.println("CloudBeaver setup health: 24 controls passed");
    }
}
