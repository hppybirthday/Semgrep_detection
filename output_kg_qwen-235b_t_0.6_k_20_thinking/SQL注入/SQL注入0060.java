import java.sql.*;
import java.util.Scanner;

public class CRMSystem {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/crm_db";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            Customer customer = getCustomerByUsername(conn, username);
            if (customer != null) {
                System.out.println("Customer found: " + customer);
            } else {
                System.out.println("Customer not found");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 易受攻击的方法：直接拼接SQL语句
    public static Customer getCustomerByUsername(Connection conn, String username) throws SQLException {
        String query = "SELECT id, name, email FROM customers WHERE name = '" + username + "'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return new Customer(rs.getInt("id"), rs.getString("name"), rs.getString("email"));
            }
            return null;
        }
    }

    // 更新客户邮箱的危险方法
    public static void updateCustomerEmail(Connection conn, int id, String newEmail) throws SQLException {
        String query = "UPDATE customers SET email = '" + newEmail + "' WHERE id = " + id;
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(query);
        }
    }

    // 客户删除的危险方法
    public static void deleteCustomer(Connection conn, String condition) throws SQLException {
        String query = "DELETE FROM customers WHERE " + condition;
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(query);
        }
    }
}

// 客户数据模型类
class Customer {
    private int id;
    private String name;
    private String email;

    public Customer(int id, String name, String email) {
        this.id = id;
        this.name = name;
        this.email = email;
    }

    @Override
    public String toString() {
        return "Customer{id=" + id + ", name='" + name + "', email='" + email + "'}";
    }
}