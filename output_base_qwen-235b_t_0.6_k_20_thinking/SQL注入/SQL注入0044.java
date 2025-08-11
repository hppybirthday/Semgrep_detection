import java.sql.*;
import java.util.Scanner;

/**
 * CRM系统用户登录模块
 * 采用防御式编程风格尝试过滤特殊字符
 */
public class CRMLogin {
    // 模拟数据库连接
    private Connection connection;

    public CRMLogin() {
        try {
            // 使用H2内存数据库模拟环境
            connection = DriverManager.getConnection(
                "jdbc:h2:mem:crm;DB_CLOSE_DELAY=-1", "sa", "");
            initializeDatabase();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 初始化测试数据
    private void initializeDatabase() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, "
                + "username VARCHAR(50), password VARCHAR(50))");
            // 插入测试数据
            stmt.execute("INSERT INTO users VALUES (1, 'admin', 'secure123')");
        }
    }

    // 用户登录验证（存在SQL注入漏洞）
    public boolean login(String username, String password) {
        // 模拟防御性输入过滤（存在缺陷）
        if (username == null || password == null || 
            username.contains(";") || password.contains(";")) {
            System.out.println("非法输入字符");
            return false;
        }

        String query = "SELECT * FROM users WHERE username = '" + 
            username + "' AND password = '" + password + "'";

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                System.out.println("登录成功！欢迎 " + rs.getString("username"));
                return true;
            } else {
                System.out.println("登录失败：用户名或密码错误");
                return false;
            }
        } catch (SQLException e) {
            System.out.println("数据库错误: " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) {
        CRMLogin crm = new CRMLogin();
        Scanner scanner = new Scanner(System.in);

        System.out.println("=== CRM系统登录 ===");
        System.out.print("用户名: ");
        String username = scanner.nextLine();
        System.out.print("密码: ");
        String password = scanner.nextLine();

        // 模拟攻击示例：输入 ' OR '1'='1 作为用户名
        crm.login(username, password);
    }
}