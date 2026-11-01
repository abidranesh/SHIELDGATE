// Shieldgate rule test fixture -- intentionally vulnerable code, never compiled or run.
import java.sql.*;

public class SqliFixture {
    public void bad(Connection conn, String name) throws SQLException {
        Statement st = conn.createStatement();
        // ruleid: shieldgate.java.sqli-jdbc-concat
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        String q = "DELETE FROM users WHERE id = " + name;
        // ruleid: shieldgate.java.sqli-jdbc-concat
        st.executeUpdate(q);
    }

    public void good(Connection conn, String name) throws SQLException {
        // ok: shieldgate.java.sqli-jdbc-concat
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
        // ok: shieldgate.java.sqli-jdbc-concat
        conn.prepareStatement("INSERT INTO users(name, admin)" + " VALUES(?, ?)");
    }
}
