import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 领域模型：游戏用户
class GameUser {
    private String username;
    private int score;

    public GameUser(String username, int score) {
        this.username = username;
        this.score = score;
    }

    // Getters and setters
}

// 仓储接口
terface UserRepository {
    List<GameUser> findUsers(String query) throws SQLException;
}

// 存在漏洞的实现
class SqlUserRepository implements UserRepository {
    private Connection connection;

    public SqlUserRepository(String dbUrl) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl);
    }

    @Override
    public List<GameUser> findUsers(String query) throws SQLException {
        List<GameUser> users = new ArrayList<>();
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT username, score FROM users WHERE username LIKE '" + query + "'" // 漏洞点
        );

        while (rs.next()) {
            users.add(new GameUser(rs.getString("username"), rs.getInt("score")));
        }
        return users;
    }
}

// 桌面游戏主类
public class GameLauncher {
    public static void main(String[] args) {
        try {
            UserRepository repo = new SqlUserRepository("jdbc:mysql://localhost:3306/game_db");
            
            // 模拟用户搜索
            System.out.println("Searching for 'admin':");
            List<GameUser> result = repo.findUsers("admin");
            System.out.println("Found " + result.size() + " users");
            
            // 攻击示例
            System.out.println("\
[Attack Simulation] Injecting malicious query...");
            String maliciousInput = "' OR '1'='1"; // 恶意输入
            List<GameUser> attackResult = repo.findUsers(maliciousInput);
            System.out.println("Attack returned " + attackResult.size() + " users");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}