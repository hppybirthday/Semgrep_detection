package com.example.bigdata;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 高抽象建模：数据实体抽象
template <T> interface DataEntity {
    T fromResultSet(ResultSet rs);
}

// 高抽象建模：通用数据访问层抽象类
abstract class DataAccessObject<T> {
    protected Connection connection;
    protected String tableName;

    public DataAccessObject(String tableName) {
        this.tableName = tableName;
        connect();
    }

    private void connect() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/bigdata_db", "user", "password");
        } catch (Exception e) {
            throw new RuntimeException("Database connection error", e);
        }
    }

    // 存在漏洞的抽象方法实现
    public List<T> queryWithFilter(String filterCondition) {
        List<T> results = new ArrayList<>();
        String query = "SELECT * FROM " + tableName + " WHERE " + filterCondition;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                results.add(mapResultSet(rs));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Query execution error", e);
        }
        return results;
    }

    protected abstract T mapResultSet(ResultSet rs);
}

// 具体业务实体：日志数据模型
class LogEntry implements DataEntity<LogEntry> {
    private String id;
    private String content;
    private String severity;

    @Override
    public LogEntry fromResultSet(ResultSet rs) {
        try {
            LogEntry entry = new LogEntry();
            entry.id = rs.getString("id");
            entry.content = rs.getString("content");
            entry.severity = rs.getString("severity");
            return entry;
        } catch (SQLException e) {
            throw new RuntimeException("Mapping error", e);
        }
    }
}

// 具体数据访问实现类
class LogDAO extends DataAccessObject<LogEntry> {
    public LogDAO() {
        super("logs");
    }

    @Override
    protected LogEntry mapResultSet(ResultSet rs) {
        return new LogEntry().fromResultSet(rs);
    }
}

// 业务服务层（模拟大数据处理场景）
class LogProcessingService {
    private LogDAO logDAO;

    public LogProcessingService() {
        logDAO = new LogDAO();
    }

    // 存在漏洞的业务方法
    public List<LogEntry> analyzeLogs(String userFilter) {
        // 直接拼接用户输入到SQL条件中
        return logDAO.queryWithFilter(userFilter);
    }
}

// 模拟漏洞触发的主程序
class Main {
    public static void main(String[] args) {
        LogProcessingService service = new LogProcessingService();
        
        // 模拟用户输入（正常用例）
        System.out.println("Normal query:");
        List<LogEntry> normalResults = service.analyzeLogs("severity = 'ERROR'");
        System.out.println("Found " + normalResults.size() + " entries");
        
        // 模拟攻击者输入（SQL注入攻击）
        System.out.println("\
Malicious injection attack:");
        String maliciousInput = "1=1; DROP TABLE logs; --";
        List<LogEntry> attackResults = service.analyzeLogs(maliciousInput);
        System.out.println("Attack query returned " + attackResults.size() + " entries");
    }
}