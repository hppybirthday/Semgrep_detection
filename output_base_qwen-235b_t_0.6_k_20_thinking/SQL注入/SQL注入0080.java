import java.sql.*;\r
import java.util.Scanner;\r
\r
public class FileEncryptionTool {\r
    public static void main(String[] args) {\r
        Scanner scanner = new Scanner(System.in);\r
        Connection conn = null;\r
        \r
        try {\r
            // 初始化数据库连接\r
            conn = DriverManager.getConnection(\r
                "jdbc:mysql://localhost:3306/file_security", "root", "password");\r
            \r
            System.out.print("请输入用户名：");\r
            String username = scanner.nextLine();\r
            \r
            System.out.print("请输入密码：");\r
            String password = scanner.nextLine();\r
            \r
            // 存在漏洞的SQL查询构造方式\r
            String query = "SELECT * FROM users WHERE username='" + username \r
                         + "' AND password='" + password + "'";\r
            \r
            Statement stmt = conn.createStatement();\r
            ResultSet rs = stmt.executeQuery(query);\r
            \r
            if (rs.next()) {\r
                System.out.println("验证成功！请选择操作：");\r
                System.out.println("1. 加密文件  2. 解密文件");\r
                int choice = scanner.nextInt();\r
                scanner.nextLine(); // 清除缓冲区\r
                \r
                if (choice == 1) {\r
                    System.out.print("请输入要加密的文件内容：");\r
                    String content = scanner.nextLine();\r
                    System.out.println("加密后的内容：" + encrypt(content));\r
                } else if (choice == 2) {\r
                    System.out.print("请输入要解密的文件内容：");\r
                    String content = scanner.nextLine();\r
                    System.out.println("解密后的内容：" + decrypt(content));\r
                }\r
            } else {\r
                System.out.println("登录失败：用户名或密码错误");\r
            }\r
            \r
        } catch (Exception e) {\r
            e.printStackTrace();\r
        } finally {\r
            try { if (conn != null) conn.close(); } catch (SQLException e) {}\r
        }\r
    }\r
    \r
    // 模拟加密算法\r
    private static String encrypt(String input) {\r
        return Base64.getEncoder().encodeToString(input.getBytes());\r
    }\r
    \r
    // 模拟解密算法\r
    private static String decrypt(String input) {\r
        return new String(Base64.getDecoder().decode(input));\r
    }\r
}