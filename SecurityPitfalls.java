import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deliberately insecure example to trigger static analyzers (Semgrep + CodeQL).
 */
public class SecurityPitfalls {

    public static void main(String[] args) throws Exception {
        // ---- 1) User-controlled input (for CodeQL taint analysis) ----
        // Environment variable wird als "user-controlled" modelliert.
        String username = System.getenv("DEMO_USERNAME");
        if (username == null) {
            // Fallback: klassischer SQLi-Payload
            username = "admin' OR '1'='1";
        }

        // ---- 2) Unsichere SQL-Konkatenation (SQL Injection) ----
        Connection connection = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
        Statement statement = connection.createStatement();

        // BAD: SQL Statement wird per String-Konkatenation gebaut
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet resultSet = statement.executeQuery(query);

        while (resultSet.next()) {
            System.out.println(resultSet.getString("username"));
        }

        resultSet.close();
        statement.close();
        connection.close();

        // ---- 3) Schwache Hashfunktion (Semgrep weak-hash) ----
        storePasswordInsecurely("superSecretPassword123");
    }

    private static void storePasswordInsecurely(String password) throws NoSuchAlgorithmException {
        // BAD: MD5 ist kryptografisch gebrochen und wird von vielen Regeln geflaggt.
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        System.out.println("Insecure MD5 digest length: " + digest.length);
    }
}
