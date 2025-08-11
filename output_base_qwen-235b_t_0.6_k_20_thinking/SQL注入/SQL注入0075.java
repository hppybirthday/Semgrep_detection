import java.sql.*;
import java.util.Scanner;

public class VulnerableBankApp {
    public static void main(String[] args) {
        String dbURL = "jdbc:mysql://localhost:3306/bankdb";
        String dbUser = "root";
        String dbPassword = "secure123";
        
        try (Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword);
             Scanner scanner = new Scanner(System.in)) {
            
            System.out.println("=== 安全银行系统 ===");
            System.out.print("请输入账户ID查询余额: ");
            String accountId = scanner.nextLine();
            
            // 漏洞点：直接拼接用户输入到SQL查询
            String query = "SELECT account_name, balance FROM accounts WHERE id = '" 
                         + accountId + "' LIMIT 1";
            
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {
                
                if (rs.next()) {
                    System.out.println("账户: " + rs.getString("account_name"));
                    System.out.println("余额: $" + rs.getDouble("balance"));
                    
                    // 模拟转账功能
                    System.out.print("输入转账目标ID: ");
                    String targetId = scanner.nextLine();
                    System.out.print("输入转账金额: ");
                    String amountStr = scanner.nextLine();
                    
                    // 更危险的漏洞：组合多个用户输入
                    String transferQuery = "UPDATE accounts SET balance = balance - " 
                                         + amountStr + " WHERE id = '" 
                                         + accountId + "'; UPDATE accounts SET balance = balance + " 
                                         + amountStr + " WHERE id = '" 
                                         + targetId + "'";
                    
                    stmt.executeUpdate(transferQuery);
                    System.out.println("转账成功!");
                } else {
                    System.out.println("账户不存在");
                }
            }
            
        } catch (SQLException e) {
            System.err.println("数据库错误: " + e.getMessage());
        }
    }
}