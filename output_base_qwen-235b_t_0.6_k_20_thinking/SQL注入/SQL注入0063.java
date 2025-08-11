import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 用户实体类
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

// 数据库操作类
class UserDAO {
    private Connection connection;

    public UserDAO(Connection conn) {
        this.connection = conn;
    }

    // 存在SQL注入漏洞的方法
    public List<User> findUsers(String username, String password) throws SQLException {
        List<User> users = new ArrayList<>();
        Statement stmt = connection.createStatement();
        // 危险的字符串拼接方式
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        while (rs.next()) {
            users.add(new User(rs.getString("username"), rs.getString("password")));
        }
        return users;
    }
}

// 模拟微服务入口点
public class UserMicroserviceApplication {
    public static void main(String[] args) {
        try {
            // 模拟数据库连接
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/cloud_db", "user", "password");
            
            UserDAO userDAO = new UserDAO(conn);
            
            // 模拟用户输入（攻击示例）
            String userInput = "admin'--";
            String passInput = "any_password";
            
            System.out.println("[+] 正在执行恶意查询...");
            List<User> result = userDAO.findUsers(userInput, passInput);
            
            if (!result.isEmpty()) {
                System.out.println("[!] 登录成功 - 绕过身份验证");
            } else {
                System.out.println("[-] 登录失败");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}