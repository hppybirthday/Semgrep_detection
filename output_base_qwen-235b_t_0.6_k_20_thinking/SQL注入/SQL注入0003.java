import java.sql.*;
import java.util.Scanner;

class DatabaseConnection {
    Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "root", "password");
    }
}

class User {
    String username;
    String password;
    
    User(String username, String password) {
        this.username = username;
        this.password = password;
    }
}

class UserService {
    DatabaseConnection dbConn;

    UserService() {
        dbConn = new DatabaseConnection();
    }

    boolean authenticateUser(User user) {
        try {
            Connection conn = dbConn.getConnection();
            Statement stmt = conn.createStatement();
            // 易受攻击的SQL拼接
            String query = "SELECT * FROM users WHERE username = '" + user.username + "' AND password = '" + user.password + "'";
            System.out.println("执行查询: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("登录成功 - 欢迎 " + rs.getString("username"));
                return true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }
}

public class TaskManager {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("请输入用户名: ");
        String username = scanner.nextLine();
        
        System.out.print("请输入密码: ");
        String password = scanner.nextLine();
        
        User user = new User(username, password);
        UserService userService = new UserService();
        
        if (!userService.authenticateUser(user)) {
            System.out.println("登录失败");
        }
        
        scanner.close();
    }
}