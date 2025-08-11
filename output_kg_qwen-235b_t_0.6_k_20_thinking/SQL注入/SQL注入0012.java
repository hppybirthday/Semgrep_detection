import java.sql.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SQLiVulnerableCRM {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            throw new RuntimeException("JDBC Driver not found");
        }
    }

    // 漏洞入口点：直接拼接用户输入到SQL查询中
    public static List<Map<String, String>> searchCustomers(String searchTerm) {
        List<Map<String, String>> results = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/crm_db", "user", "password");
             Statement stmt = conn.createStatement()) {
            
            // 漏洞点：直接拼接用户输入到SQL语句
            String query = "SELECT id, name, email FROM customers WHERE name LIKE '%" 
                          + searchTerm + "%' ORDER BY name";
            
            System.out.println("Executing query: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                Map<String, String> row = new HashMap<>();
                row.put("id", rs.getString("id"));
                row.put("name", rs.getString("name"));
                row.put("email", rs.getString("email"));
                results.add(row);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return results;
    }

    // 模拟Web控制器方法
    public static void handleCustomerSearch(String userInput) {
        // 模拟用户输入处理
        List<Map<String, String>> customers = searchCustomers(userInput);
        customers.forEach(customer -> 
            System.out.printf("Found: %s (%s)\
", 
                customer.get("name"), customer.get("email"))
        );
    }

    // 主方法模拟攻击场景
    public static void main(String[] args) {
        System.out.println("=== Vulnerable CRM System ===");
        
        // 正常查询示例
        System.out.println("\
Normal search for 'John':");
        handleCustomerSearch("John");
        
        // 恶意注入示例：UNION攻击
        System.out.println("\
Malicious UNION attack:");
        String unionAttack = "' UNION SELECT 'HACKER', 'admin@hack.com', '1=1' -- ";
        handleCustomerSearch(unionAttack);
        
        // 恶意注入示例：删除表
        System.out.println("\
Malicious DROP TABLE attempt:");
        String dropAttack = "'; DROP TABLE customers; -- ";
        handleCustomerSearch(dropAttack);
    }
}