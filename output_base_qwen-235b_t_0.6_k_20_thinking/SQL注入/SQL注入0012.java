import java.sql.*;
import java.util.function.Consumer;

public class CRMSystem {
    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static Connection connect() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:crm.db");
    }

    static void createTable() {
        executeQuery(conn -> {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, name TEXT, email TEXT)");
            } catch (SQLException e) {
                System.err.println("创建表失败: " + e.getMessage());
            }
        });
    }

    static void executeQuery(Consumer<Connection> action) {
        try (Connection conn = connect()) {
            action.accept(conn);
        } catch (SQLException e) {
            System.err.println("数据库连接失败: " + e.getMessage());
        }
    }

    static void findCustomer(String id) {
        String query = String.format("SELECT * FROM customers WHERE id = '%s'", id);
        executeQuery(conn -> {
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {
                
                System.out.println("查询结果:");
                while (rs.next()) {
                    System.out.printf("ID: %s, 名称: %s, 邮箱: %s\
",
                        rs.getString("id"),
                        rs.getString("name"),
                        rs.getString("email"));
                }
            } catch (SQLException e) {
                System.err.println("查询失败: " + e.getMessage());
            }
        });
    }

    public static void main(String[] args) {
        createTable();
        
        // 初始化测试数据
        executeQuery(conn -> {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("INSERT OR IGNORE INTO customers VALUES ('C1001', '张三', 'zhangsan@example.com')");
                stmt.execute("INSERT OR IGNORE INTO customers VALUES ('C1002', '李四', 'lisi@example.com')");
            } catch (SQLException e) {
                System.err.println("初始化数据失败: " + e.getMessage());
            }
        });
        
        // 模拟用户输入（存在漏洞的场景）
        System.out.println("--- 正常查询 ---");
        findCustomer("C1001");
        
        System.out.println("\
--- SQL注入攻击测试 ---");
        String maliciousInput = "' OR '1'='1"; // 恶意外部输入
        findCustomer(maliciousInput);
    }
}