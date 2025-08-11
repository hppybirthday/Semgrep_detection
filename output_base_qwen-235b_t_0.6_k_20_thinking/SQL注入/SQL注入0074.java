import java.sql.*;
import java.util.Scanner;

public class DataCleaner {
    private Connection connection;

    public DataCleaner(String dbUrl, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, user, password);
    }

    // 模拟数据清洗：删除包含非法字符的记录
    public void cleanInvalidData(String tableName, String columnName) {
        String query = "DELETE FROM " + tableName + " WHERE " + columnName + " LIKE '%特殊字符%'";
        try (Statement stmt = connection.createStatement()) {
            System.out.println("执行清洗语句: " + query);
            stmt.executeUpdate(query);
            System.out.println("数据清洗完成");
        } catch (SQLException e) {
            System.err.println("数据清洗失败: " + e.getMessage());
        }
    }

    // 模拟防御式编程的输入验证（存在缺陷）
    private boolean isValidIdentifier(String input) {
        // 错误地认为只允许字母数字的输入验证
        return input != null && input.matches("[a-zA-Z0-9_]+$$;
    }

    public static void main(String[] args) {
        try {
            DataCleaner cleaner = new DataCleaner(
                "jdbc:mysql://localhost:3306/company_db",
                "admin",
                "securePass123"
            );

            Scanner scanner = new Scanner(System.in);
            System.out.print("请输入要清洗的表名: ");
            String table = scanner.nextLine();
            System.out.print("请输入要清洗的列名: ");
            String column = scanner.nextLine();

            // 调用存在漏洞的清洗方法
            cleaner.cleanInvalidData(table, column);

        } catch (SQLException e) {
            System.err.println("数据库连接失败: " + e.getMessage());
        }
    }
}

/*
数据库初始化脚本:
CREATE DATABASE company_db;
USE company_db;
CREATE TABLE employees (id INT PRIMARY KEY, name VARCHAR(100), position VARCHAR(100));
INSERT INTO employees VALUES (1, '张三_特殊字符', 'Engineer'), (2, '李四', 'Manager');
*/