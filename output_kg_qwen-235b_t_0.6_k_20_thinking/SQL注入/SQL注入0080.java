import java.sql.*;
import java.util.Scanner;

public class FileEncryptionTool {
    private static Connection connection;

    public static void main(String[] args) {
        try {
            connectToDatabase();
            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.println("\
=== 文件加密解密工具 ===");
                System.out.println("1. 登录");
                System.out.println("2. 退出");
                System.out.print("请选择操作: ");
                int choice = scanner.nextInt();
                scanner.nextLine(); // 清除缓冲区

                switch (choice) {
                    case 1:
                        login(scanner);
                        break;
                    case 2:
                        System.out.println("退出程序");
                        return;
                    default:
                        System.out.println("无效选择");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void connectToDatabase() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/encryption_db";
        String user = "root";
        String password = "password";
        connection = DriverManager.getConnection(url, user, password);
    }

    private static void login(Scanner scanner) throws SQLException {
        System.out.print("请输入用户名: ");
        String username = scanner.nextLine();
        System.out.print("请输入密码: ");
        String password = scanner.nextLine();

        // 存在SQL注入漏洞的查询方式
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(query);

        if (resultSet.next()) {
            System.out.println("登录成功! 欢迎 " + username);
            showEncryptionMenu(scanner);
        } else {
            System.out.println("登录失败: 无效的用户名或密码");
        }
    }

    private static void showEncryptionMenu(Scanner scanner) {
        while (true) {
            System.out.println("\
=== 加密操作 ===");
            System.out.println("1. 加密文件");
            System.out.println("2. 解密文件");
            System.out.println("3. 返回主菜单");
            System.out.print("请选择操作: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // 清除缓冲区

            switch (choice) {
                case 1:
                    encryptFile(scanner);
                    break;
                case 2:
                    decryptFile(scanner);
                    break;
                case 3:
                    return;
                default:
                    System.out.println("无效选择");
            }
        }
    }

    private static void encryptFile(Scanner scanner) {
        System.out.print("请输入要加密的文件名: ");
        String filename = scanner.nextLine();
        System.out.println("正在加密文件: " + filename);
        // 模拟加密过程
        System.out.println("加密成功! 生成加密文件: " + filename + ".enc");
    }

    private static void decryptFile(Scanner scanner) {
        System.out.print("请输入要解密的文件名: ");
        String filename = scanner.nextLine();
        System.out.println("正在解密文件: " + filename);
        // 模拟解密过程
        System.out.println("解密成功! 生成原始文件: " + filename.replace(".enc", ""));
    }
}