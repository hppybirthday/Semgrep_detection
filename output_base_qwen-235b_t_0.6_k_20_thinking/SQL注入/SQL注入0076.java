import java.sql.*;
import java.util.Scanner;

public class CRMApp {
    public static void main(String[] args) {
        Connection conn = null;
        try {
            // 快速原型开发常用的H2内存数据库
            conn = DriverManager.getConnection(
                "jdbc:h2:mem:crm;DB_CLOSE_DELAY=-1", "sa", "");
            Statement stmt = conn.createStatement();
            // 初始化客户表
            stmt.execute("CREATE TABLE IF NOT EXISTS customers (id INT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255))");
            // 插入测试数据
            try {
                stmt.execute("INSERT INTO customers VALUES (1, 'Acme Corp', 'contact@acme.com')");
                stmt.execute("INSERT INTO customers VALUES (2, 'Test Company', 'test@test.com')");
            } catch (SQLException e) {}

            Scanner scanner = new Scanner(System.in);
            System.out.println("=== CRM 客户查询系统 ===");
            System.out.print("请输入客户名称: ");
            String customerName = scanner.nextLine();
            
            // 存在SQL注入漏洞的代码
            String query = "SELECT * FROM customers WHERE name = '" + customerName + "'";
            System.out.println("执行查询: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            System.out.println("\
查询结果:");
            while (rs.next()) {
                System.out.println("ID: " + rs.getInt("id") + ", " + 
                                 "名称: " + rs.getString("name") + ", " + 
                                 "邮箱: " + rs.getString("email"));
            }
            
            rs.close();
            stmt.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}