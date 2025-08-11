import java.sql.*;
import java.util.*;

// 高抽象建模风格的游戏数据库操作类
class GameDatabase {
    private Connection connection;

    public GameDatabase() {
        try {
            // 硬编码数据库连接信息（安全隐患）
            String url = "jdbc:mysql://localhost:3306/board_games";
            String user = "root";
            String password = "dev123456";
            connection = DriverManager.getConnection(url, user, password);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 存在漏洞的玩家验证方法
    public boolean validatePlayer(String username, String password) {
        try {
            Statement stmt = connection.createStatement();
            // 危险的字符串拼接（漏洞核心）
            String query = "SELECT * FROM players WHERE username='" + username + "' AND password='" + password + "'";
            System.out.println("执行SQL: " + query);
            ResultSet rs = stmt.executeQuery(query);
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // 玩家数据访问类
    static class PlayerDAO {
        private GameDatabase db;

        public PlayerDAO(GameDatabase db) {
            this.db = db;
        }

        // 存在漏洞的查询方法
        public List<String> getPlayerStats(String playerName) {
            List<String> stats = new ArrayList<>();
            try {
                Statement stmt = db.connection.createStatement();
                // 二次注入点
                String query = "SELECT * FROM game_stats WHERE player_id=(SELECT id FROM players WHERE username='" + playerName + "')";
                ResultSet rs = stmt.executeQuery(query);
                while (rs.next()) {
                    stats.add("游戏: " + rs.getString("game_name") + ", 得分: " + rs.getInt("score"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return stats;
        }
    }

    public static void main(String[] args) {
        GameDatabase db = new GameDatabase();
        PlayerDAO playerDAO = new PlayerDAO(db);

        // 模拟用户输入（测试用例）
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 桌面游戏登录系统 ===");
        System.out.print("用户名: ");
        String user = scanner.nextLine();
        System.out.print("密码: ");
        String pass = scanner.nextLine();

        // 触发漏洞
        if (db.validatePlayer(user, pass)) {
            System.out.println("登录成功!");
            System.out.println("\
玩家统计数据:");
            playerDAO.getPlayerStats(user).forEach(System.out::println);
        } else {
            System.out.println("登录失败");
        }
    }
}