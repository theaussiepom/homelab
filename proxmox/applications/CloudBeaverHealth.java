import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/** Fixed loopback-only setup check using the JDK already present in the CE image. */
class CloudBeaverHealth {
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
            if (args.length > 1 || (args.length == 1 && !args[0].equals("--configuration"))) {
                throw new IllegalArgumentException();
            }
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
                if (args.length == 1) System.out.println(body);
            }
        } catch (Exception error) {
            System.err.println("CloudBeaver setup health refused");
            System.exit(1);
        }
    }
}
