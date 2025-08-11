import java.sql.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请输入数据库URL（原型开发使用默认配置）:");
        String url = scanner.nextLine();
        System.out.println("请输入用户名:");
        String user = scanner.nextLine();
        System.out.println("请输入密码:");
        String password = scanner.nextLine();

        try (Connection conn = DriverManager.getConnection(
                url.isEmpty() ? "jdbc:mysql://localhost:3306/company_db" : url,
                user.isEmpty() ? "root" : user,
                password)) {
            
            System.out.println("请选择操作：1.清理空值 2.修复异常数据");
            int choice = Integer.parseInt(scanner.nextLine());
            
            if (choice == 1) {
                System.out.println("请输入要清理的表名:");
                String tableName = scanner.nextLine();
                System.out.println("请输入要检查的列名:");
                String columnName = scanner.nextLine();
                cleanData(conn, tableName, columnName);
            } 
            else if (choice == 2) {
                System.out.println("请输入需要修复的表名:");
                String tableName = scanner.nextLine();
                System.out.println("请输入修复条件（SET子句）:");
                String updateClause = scanner.nextLine();
                fixAnomalies(conn, tableName, updateClause);
            }
            
        } catch (Exception e) {
            System.out.println("数据清洗异常: " + e.getMessage());
        }
    }

    // 清理空值方法（存在SQL注入漏洞）
    private static void cleanData(Connection conn, String tableName, String columnName) throws SQLException {
        String sql = "DELETE FROM " + tableName + " WHERE " + columnName + " IS NULL";
        try (Statement stmt = conn.createStatement()) {
            int rowsAffected = stmt.executeUpdate(sql);
            System.out.println("已清理 " + rowsAffected + " 条空值记录");
        }
    }

    // 修复异常数据方法（存在SQL注入漏洞）
    private static void fixAnomalies(Connection conn, String tableName, String updateClause) throws SQLException {
        String sql = "UPDATE " + tableName + " " + updateClause;
        try (Statement stmt = conn.createStatement()) {
            int rowsAffected = stmt.executeUpdate(sql);
            System.out.println("已修复 " + rowsAffected + " 条异常数据");
        }
    }
}
// 编译方式：javac -cp mysql-connector-java-8.0.26.jar DataCleaner.java
// 运行方式：java -cp .;mysql-connector-java-8.0.26.jar DataCleaner