import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Deliberately insecure sample to trigger security scanners.
 */
public class SecurityPitfalls {
    // Hard-coded AWS credentials for Gitleaks to detect.
    private static final String GITHUB_TOKEN = "02290a2a-7f5a-4836-8745-d4d797e475d0";


    public static void main(String[] args) throws Exception {
        String userInput = args.length > 0 ? args[0] : "' OR '1'='1";

        Connection connection = null;
        Statement statement = null;
        ResultSet resultSet = null;

        try {
            connection = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            statement = connection.createStatement();

            // Unsafe string concatenation that should trigger Semgrep + CodeQL SQL injection rules.
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            resultSet = statement.executeQuery(query);

            while (resultSet.next()) {
                System.out.println(resultSet.getString("username"));
            }
        } finally {
            if (resultSet != null) {
                resultSet.close();
            }
            if (statement != null) {
                statement.close();
            }
            if (connection != null) {
                connection.close();
            }
        }
    }
}
