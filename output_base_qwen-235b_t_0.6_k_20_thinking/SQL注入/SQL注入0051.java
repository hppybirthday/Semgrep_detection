import java.sql.*;
import java.util.Scanner;

public class TaskManager {
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // 初始化数据库连接
            connection = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
            initializeDatabase();

            Scanner scanner = new Scanner(System.in);
            System.out.println("=== 任务管理系统 ===");
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();

            // 存在漏洞的登录验证
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                System.out.println("登录成功！欢迎 " + username);
                showTasks(username);
            } else {
                System.out.println("登录失败: 无效的用户名或密码");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initializeDatabase() throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
        stmt.execute("INSERT INTO users VALUES (1, 'admin', 'admin123'), (2, 'user', 'password123')");
        
        stmt.execute("CREATE TABLE tasks (id INT PRIMARY KEY, username VARCHAR(50), task VARCHAR(255))");
        stmt.execute("INSERT INTO tasks VALUES (1, 'admin', '完成安全审计'), (2, 'user', '更新文档')");
    }

    private static void showTasks(String username) throws SQLException {
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT task FROM tasks WHERE username = '" + username + "'");
        
        System.out.println("\
您的任务:");
        while (rs.next()) {
            System.out.println("- " + rs.getString("task"));
        }
    }
}