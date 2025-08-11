package com.example.bigdata.log;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 领域模型
public class LogRecord {
    private String id;
    private String userId;
    private String action;
    private String timestamp;
    
    // 构造方法/getter/setter省略
    public LogRecord(String id, String userId, String action, String timestamp) {
        this.id = id;
        this.userId = userId;
        this.action = action;
        this.timestamp = timestamp;
    }
}

// 仓储接口
interface LogRepository {
    List<LogRecord> findByCriteria(String criteria) throws SQLException;
}

// 具体实现
class JdbcLogRepository implements LogRepository {
    private Connection connection;

    public JdbcLogRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public List<LogRecord> findByCriteria(String criteria) throws SQLException {
        List<LogRecord> results = new ArrayList<>();
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM logs WHERE " + criteria;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        while (rs.next()) {
            results.add(new LogRecord(
                rs.getString("id"),
                rs.getString("user_id"),
                rs.getString("action"),
                rs.getString("timestamp")
            ));
        }
        return results;
    }
}

// 服务层
class LogAnalysisService {
    private LogRepository repository;

    public LogAnalysisService(LogRepository repository) {
        this.repository = repository;
    }

    public List<LogRecord> analyzeUserActivity(String userId) throws SQLException {
        // 构造不安全的查询条件
        String criteria = "user_id = '" + userId + "' ORDER BY timestamp DESC";
        return repository.findByCriteria(criteria);
    }
}

// 主程序
public class LogProcessor {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
            createTable(conn);
            
            LogRepository repo = new JdbcLogRepository(conn);
            LogAnalysisService service = new LogAnalysisService(repo);
            
            // 模拟用户输入
            String userInput = "test_user' OR '1'='1"; // 恶意输入示例
            List<LogRecord> logs = service.analyzeUserActivity(userInput);
            
            System.out.println("Found " + logs.size() + " records");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void createTable(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS logs (id VARCHAR(36), user_id VARCHAR(50), action VARCHAR(100), timestamp VARCHAR(30))");
    }
}