import java.sql.*;
import java.util.Scanner;

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

// 数据访问层
class UserDAO {
    private Connection connection;

    public UserDAO() {
        try {
            // 模拟数据库连接
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/bank_db",
                "root",
                "password"
            );
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 存在SQL注入漏洞的登录方法
    public User login(String username, String password) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                return new User(rs.getString("username"), rs.getString("password"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
}

// 业务服务类
class AuthService {
    private UserDAO userDAO = new UserDAO();

    public boolean authenticate(String username, String password) {
        User user = userDAO.login(username, password);
        return user != null;
    }
}

// 模拟客户端
public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        AuthService authService = new AuthService();

        System.out.println("=== 银行系统登录 ===");
        System.out.print("用户名: ");
        String username = scanner.nextLine();
        
        System.out.print("密码: ");
        String password = scanner.nextLine();

        if (authService.authenticate(username, password)) {
            System.out.println("登录成功！欢迎访问银行系统。");
            // 模拟后续敏感操作
            System.out.println("[系统提示] 当前账户余额: ¥99999999.99");
        } else {
            System.out.println("登录失败: 凭证无效");
        }
    }
}