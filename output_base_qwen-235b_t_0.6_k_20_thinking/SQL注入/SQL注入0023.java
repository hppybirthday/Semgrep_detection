import java.sql.*;
import java.util.Scanner;

// 玩家类
class Player {
    private int id;
    private String username;
    private int score;

    public Player(String username, int score) {
        this.username = username;
        this.score = score;
    }

    // 数据库管理类
    static class DatabaseManager {
        private Connection conn;

        public DatabaseManager() throws SQLException {
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/game_db", "root", "password");
        }

        // 易受攻击的登录验证方法
        public boolean validateUser(String username, String password) throws SQLException {
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM players WHERE username = '" + username + "' AND password = '" + password + "'";
            System.out.println("执行SQL: " + query);
            ResultSet rs = stmt.executeQuery(query);
            return rs.next();
        }

        // 易受攻击的分数更新方法
        public void updateScore(String username, int newScore) throws SQLException {
            Statement stmt = conn.createStatement();
            String query = "UPDATE players SET score = " + newScore + " WHERE username = '" + username + "'";
            System.out.println("执行SQL: " + query);
            stmt.executeUpdate(query);
        }

        public void close() throws SQLException {
            if (conn != null) conn.close();
        }
    }

    // 游戏主类
    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in);
             DatabaseManager db = new DatabaseManager()) {

            System.out.println("=== 桌面游戏登录 ===");
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();

            if (db.validateUser(username, password)) {
                System.out.println("登录成功!");
                System.out.print("请输入新分数: ");
                int newScore = Integer.parseInt(scanner.nextLine());
                db.updateScore(username, newScore);
                System.out.println("分数更新成功!");
            } else {
                System.out.println("登录失败!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}