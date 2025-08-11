import java.io.IOException;
import java.sql.*;
import java.util.Properties;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;

public class UserManagement {
    private DataSource dataSource;

    public UserManagement() {
        Properties props = new Properties();
        props.setProperty("url", "jdbc:h2:mem:testdb");
        props.setProperty("user", "sa");
        props.setProperty("password", "");
        dataSource = new JdbcDataSource();
        ((JdbcDataSource) dataSource).setURL(props.getProperty("url"));
        ((JdbcDataSource) dataSource).setUser(props.getProperty("user"));
        ((JdbcDataSource) dataSource).setPassword(props.getProperty("password"));
    }

    public boolean authenticate(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        UserManagement um = new UserManagement();
        // 模拟API请求
        String userInputUsername = "admin'--";  // 恶意输入
        String userInputPassword = "random";
        boolean isAuthenticated = um.authenticate(userInputUsername, userInputPassword);
        System.out.println("Authentication result: " + isAuthenticated);
    }
}

// 模拟Spring Boot Controller
class AuthController {
    private UserManagement userManagement = new UserManagement();

    public void handleLogin(String username, String password) throws IOException {
        if (userManagement.authenticate(username, password)) {
            System.out.println("Login successful for: " + username);
        } else {
            System.out.println("Login failed for: " + username);
        }
    }
}

// 数据库初始化脚本
class DBInitializer {
    public static void initDB(DataSource dataSource) {
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            stmt.execute("INSERT INTO users (id, username, password) VALUES (1, 'admin', 'securepass')");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}