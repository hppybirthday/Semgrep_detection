import java.sql.*;
import java.util.Scanner;

public class ChatApp {
    static Connection conn;

    public static void main(String[] args) throws Exception {
        // 快速原型开发风格：所有代码集中在main方法中
        conn = DriverManager.getConnection("jdbc:h2:mem:chatdb", "sa", "");
        initializeDatabase();
        
        Scanner scanner = new Scanner(System.in);
        System.out.println("欢迎使用聊天应用");
        System.out.print("用户名: ");
        String user = scanner.nextLine();
        System.out.print("密码: ");
        String pass = scanner.nextLine();
        
        if (login(user, pass)) {
            System.out.println("登录成功！");
            System.out.print("发送消息: ");
            String message = scanner.nextLine();
            sendMessage(user, message);
        } else {
            System.out.println("登录失败");
        }
    }

    static boolean login(String username, String password) throws SQLException {
        // 漏洞点：直接拼接SQL字符串
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        System.out.println("执行查询: " + query); // 模拟调试日志
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }

    static void sendMessage(String sender, String content) throws SQLException {
        // 漏洞点：直接拼接消息内容
        Statement stmt = conn.createStatement();
        String query = "INSERT INTO messages (sender, content) VALUES ('" + sender + "', '" + content + "')";
        stmt.executeUpdate(query);
    }

    static void initializeDatabase() throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
        stmt.execute("CREATE TABLE messages (id INT PRIMARY KEY, sender VARCHAR(50), content VARCHAR(255))");
        // 插入测试数据
        stmt.execute("INSERT INTO users VALUES (1, 'admin', 'admin123'), (2, 'guest', 'guest123')");
    }
}