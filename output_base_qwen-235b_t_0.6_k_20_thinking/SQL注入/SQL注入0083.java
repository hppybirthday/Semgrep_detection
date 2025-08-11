import java.sql.*;
import java.util.Scanner;

// 用户类
class User {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // 模拟用户登录验证（存在SQL注入漏洞）
    public boolean validate() {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "root", "pass123");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next(); // 如果存在记录则验证成功
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}

// 任务管理类
class TaskManager {
    public void createTask(String title, String description, String username) {
        String query = "INSERT INTO tasks (title, description, assigned_to) VALUES ('" + title + "', '" + description + "', '" + username + "')";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "root", "pass123");
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(query);
            System.out.println("任务创建成功");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// 主程序
public class Main {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 任务管理系统 ===");
        System.out.print("用户名: ");
        String username = scanner.nextLine();
        System.out.print("密码: ");
        String password = scanner.nextLine();

        User user = new User(username, password);
        if (user.validate()) {
            System.out.println("登录成功");
            TaskManager tm = new TaskManager();
            System.out.print("任务标题: ");
            String title = scanner.nextLine();
            System.out.print("任务描述: ");
            String desc = scanner.nextLine();
            tm.createTask(title, desc, username);
        } else {
            System.out.println("登录失败");
        }
    }
}