import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.http.*;

public class CodeQlTestServlet extends HttpServlet {

    // Hartecodiertes Passwort → Kandidat für java/hardcoded-credentials
    private static final String PASSWORD = "SuperSecret123";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // 1) SQL Injection (java/sql-injection)
            String username = request.getParameter("username"); // bekannte Source
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE name = '" + username + "'";
            ResultSet rs = stmt.executeQuery(sql);

            // 2) Path Traversal (java/path-injection)
            String file = request.getParameter("file"); // Source
            Path p = Paths.get("/var/data/" + file);
            String content = Files.readString(p);

            // 3) Schwache Krypto (java/weak-cryptographic-algorithm)
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(content.getBytes());
            byte[] hash = md.digest();

            response.getWriter().println("OK");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
