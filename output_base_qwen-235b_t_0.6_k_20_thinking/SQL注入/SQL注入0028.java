import java.sql.*;
import java.util.Scanner;

public class CRMLogin {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("用户名: ");
        String user = sc.nextLine();
        System.out.print("密码: ");
        String pass = sc.nextLine();
        
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/crm_db", "root", "dbpass");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + user + 
                          "' AND password='" + pass + "'";
            System.out.println("执行SQL: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            if(rs.next()) {
                System.out.println("登录成功! 欢迎 " + rs.getString("fullname"));
                if(rs.getString("role").equals("admin")) {
                    System.out.println("[管理员功能已启用]");
                    String action = "DELETE FROM customers WHERE create_time < '2020-01-01'";
                    stmt.executeUpdate(action);
                }
            } else {
                System.out.println("认证失败");
            }
        } catch(Exception e) {
            System.out.println("数据库错误: " + e.getMessage());
        }
    }
}