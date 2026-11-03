import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;
import java.util.HexFormat;

/** Fixed maintenance reads using the already installed, pinned JDBC drivers. */
class CloudBeaverDatabaseHealth {
    static void need(boolean value) throws Exception {
        if (!value) throw new Exception("Database administrator readiness refused");
    }

    static void ipv4(String value) throws Exception {
        need(value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}"));
        for (String field : value.split("\\.")) need(Integer.parseInt(field) <= 255);
    }

    public static void main(String[] args) {
        try {
            need(args.length >= 4 && (args[0].equals("postgresql") || args[0].equals("mariadb")));
            boolean pg = args[0].equals("postgresql");
            need(args.length == (pg ? 4 : 7));
            ipv4(args[1]); ipv4(args[2]);
            need(args[3].matches("[a-z][a-z0-9_-]{0,62}"));
            byte[] input = System.in.readNBytes(128);
            String secret = new String(input, StandardCharsets.US_ASCII);
            need(secret.matches("[0-9a-f]{64}\\n"));
            if (!pg) {
                need(args[4].matches("3\\.5\\.[0-9]{1,3}") && args[5].matches("[0-9a-f]{64}")
                    && args[6].matches("mariadb-java-client-[0-9]+\\.[0-9]+\\.[0-9]+\\.jar"));
                need(Integer.parseInt(args[4].split("\\.")[2]) >= 11);
                Path directory = Path.of("/opt/cloudbeaver/drivers/mariadb");
                try (var files = Files.list(directory)) {
                    var jars = files.filter(path -> path.getFileName().toString().endsWith(".jar")).toList();
                    need(jars.size() == 1 && jars.get(0).getFileName().toString().equals(args[6]));
                    Path jar = jars.get(0);
                    need(Files.isRegularFile(jar, LinkOption.NOFOLLOW_LINKS) && Files.size(jar) <= 16*1024*1024);
                    need(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar))).equals(args[5]));
                }
            }
            Class<?> driver = Class.forName(pg ? "org.postgresql.Driver" : "org.mariadb.jdbc.Driver");
            String version = driver.getPackage().getImplementationVersion();
            if (pg) need(version != null && version.matches("42\\.7\\.[0-9]{1,3}")
                         && Integer.parseInt(version.split("\\.")[2]) >= 13);
            String url = pg ? "jdbc:postgresql://"+args[1]+":5432/postgres?sslmode=require&channelBinding=require&requireAuth=scram-sha-256&connectTimeout=5&socketTimeout=5"
                            : "jdbc:mariadb://"+args[1]+":3306/?sslMode=verify-full&connectTimeout=5000&socketTimeout=5000";
            Properties properties = new Properties();
            properties.setProperty("user", args[3]); properties.setProperty("password", secret.substring(0, 64));
            DriverManager.setLoginTimeout(5);
            try (Connection connection = DriverManager.getConnection(url, properties);
                 Statement statement = connection.createStatement()) {
                need(!connection.getMetaData().getURL().contains(secret.substring(0, 64)));
                need(connection.getMetaData().getDriverVersion().equals(pg ? version : args[4]));
                statement.setQueryTimeout(5);
                if (pg) {
                    try (ResultSet row = statement.executeQuery("SELECT current_user,host(inet_client_addr()),r.rolsuper,r.rolcreatedb,"
                        +"r.rolcreaterole,r.rolreplication,r.rolbypassrls,s.ssl FROM pg_roles r JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=current_user")) {
                        need(row.next() && args[3].equals(row.getString(1)) && args[2].equals(row.getString(2)));
                        for (int index = 3; index <= 8; index++) need(row.getBoolean(index));
                        need(!row.next());
                    }
                } else {
                    try (ResultSet row = statement.executeQuery("SELECT CURRENT_USER()")) {
                        need(row.next() && (args[3]+"@"+args[2]).equals(row.getString(1)) && !row.next());
                    }
                    try (ResultSet row = statement.executeQuery("SHOW SESSION STATUS LIKE 'Ssl_cipher'")) {
                        need(row.next() && !row.getString(2).isEmpty() && !row.next());
                    }
                    try (ResultSet row = statement.executeQuery("SHOW GRANTS")) {
                        need(row.next()); String grant = row.getString(1);
                        need(grant.length() <= 8192 && grant.startsWith("GRANT ALL PRIVILEGES ON *.* TO `"+args[3]+"`@`"+args[2]+"`")
                            && grant.contains(" REQUIRE SSL") && grant.endsWith(" WITH GRANT OPTION") && !row.next());
                    }
                }
            }
            System.out.println("{\"database_administrator\":\"verified\",\"encrypted\":true,\"source_match\":true}");
        } catch (Exception ignored) {
            System.err.println("Database administrator connection refused");
            System.exit(1);
        }
    }
}
