import java.sql.*;
import java.util.*;

// 领域模型
class Player {
    private String username;
    private String password;

    public Player(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }
}

// 仓储接口
terface PlayerRepository {
    boolean validatePlayer(String username, String password);
}

// 基础设施实现
class JdbcPlayerRepository implements PlayerRepository {
    private Connection connection;

    public JdbcPlayerRepository() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:game.db");
            initializeDatabase();
        } catch (ClassNotFoundException | SQLException e) {
            throw new RuntimeException("数据库初始化失败", e);
        }
    }

    private void initializeDatabase() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS players (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
            // 插入测试数据
            stmt.execute("INSERT OR IGNORE INTO players (username, password) VALUES ('admin', 'admin123')");
        }
    }

    @Override
    public boolean validatePlayer(String username, String password) {
        String query = "SELECT * FROM players WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }
}

// 领域服务
class GameService {
    private PlayerRepository playerRepository;

    public GameService(PlayerRepository playerRepository) {
        this.playerRepository = playerRepository;
    }

    public boolean loginPlayer(String username, String password) {
        return playerRepository.validatePlayer(username, password);
    }
}

// 应用入口
public class GameApplication {
    public static void main(String[] args) {
        try {
            PlayerRepository repo = new JdbcPlayerRepository();
            GameService gameService = new GameService(repo);

            Scanner scanner = new Scanner(System.in);
            System.out.print("请输入用户名: ");
            String username = scanner.nextLine();
            System.out.print("请输入密码: ");
            String password = scanner.nextLine();

            if (gameService.loginPlayer(username, password)) {
                System.out.println("登录成功！欢迎 " + username);
            } else {
                System.out.println("登录失败");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}