import java.sql.*;
import java.util.Scanner;

// 高抽象建模风格的用户类
class User {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }
}

// 数据访问层抽象
class UserDAO {
    private Connection connection;

    public UserDAO(Connection conn) {
        this.connection = conn;
    }

    // 漏洞点：不安全的SQL查询
    public boolean validateUser(User user) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + user.getUsername() + "' AND password = '" + user.getPassword() + "'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        }
    }
}

// 业务逻辑层
class TaskService {
    private UserDAO userDAO;

    public TaskService(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    public boolean authenticateUser(String username, String password) {
        try {
            return userDAO.validateUser(new User(username, password));
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}

// 主程序入口
public class VulnerableTaskManager {
    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "root", "password")) {
            TaskService taskService = new TaskService(new UserDAO(conn));
            Scanner scanner = new Scanner(System.in);

            System.out.println("=== 任务管理系统登录 ===");
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();

            if (taskService.authenticateUser(username, password)) {
                System.out.println("登录成功！");
                // 实际应用中可能访问敏感数据或执行危险操作
            } else {
                System.out.println("登录失败");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}