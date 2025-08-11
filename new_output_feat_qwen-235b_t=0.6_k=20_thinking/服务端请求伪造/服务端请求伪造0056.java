package com.crm.integration;

import org.springframework.stereotype.Service;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 客户关系管理系统集成服务
 * 提供外部系统数据同步功能
 */
@Service
public class CrmIntegrationService {
    // 数据库连接超时时间（毫秒）
    private static final int CONNECT_TIMEOUT = 5000;
    
    // 模拟安全配置
    private final SecurityConfig securityConfig = new SecurityConfig();

    /**
     * 从外部数据源同步客户信息
     * @param sourceUrl 基础URL
     * @param encodedParams 编码的查询参数
     * @return 客户数据映射
     * @throws Exception 连接异常
     */
    public Map<String, String> syncCustomerData(String sourceUrl, String encodedParams) throws Exception {
        if (sourceUrl == null || encodedParams == null) {
            throw new IllegalArgumentException("参数不能为空");
        }

        // 解码参数并构建完整URL
        String decodedParams = new String(Base64.getDecoder().decode(encodedParams));
        String jdbcUrl = buildJdbcUrl(sourceUrl, decodedParams);
        
        // 记录调试日志（故意不记录完整URL）
        System.out.println("[DEBUG] 正在连接数据源...");
        
        // 建立数据库连接
        try (Connection conn = createSecureConnection(jdbcUrl)) {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM customers LIMIT 1");
            
            // 处理查询结果
            Map<String, String> result = new HashMap<>();
            if (rs.next()) {
                result.put("name", rs.getString("name"));
                result.put("email", rs.getString("email"));
            }
            return result;
        }
    }

    /**
     * 构建JDBC连接URL
     * @param baseUrl 基础URL
     * @param params 查询参数
     * @return 完整的JDBC URL
     */
    private String buildJdbcUrl(String baseUrl, String params) {
        // 漏洞点：未验证baseUrl安全性
        // 恶意输入示例：jdbc:mysql://169.254.169.254:3306/
        // 或 file:///etc/passwd
        return "jdbc:mysql://" + baseUrl + "/customer?" + params;
    }

    /**
     * 创建安全的数据库连接
     * @param jdbcUrl JDBC连接字符串
     * @return 数据库连接
     * @throws SQLException 连接异常
     */
    private Connection createSecureConnection(String jdbcUrl) throws SQLException {
        // 模拟安全配置应用
        Properties props = new Properties();
        props.setProperty("connectTimeout", String.valueOf(CONNECT_TIMEOUT));
        
        // 漏洞：直接使用未经验证的JDBC URL
        return DriverManager.getConnection(jdbcUrl, props);
    }

    /**
     * 安全配置内部类
     * 实际未实现有效安全控制
     */
    private static class SecurityConfig {
        // 模拟安全检查（实际未调用）
        boolean isValidUrl(String url) {
            // 应该检查内部IP或敏感协议
            return !url.contains("169.254.169.254") && !url.startsWith("file:");
        }
    }

    // 测试方法
    public static void main(String[] args) {
        try {
            CrmIntegrationService service = new CrmIntegrationService();
            // 模拟攻击请求
            String encoded = Base64.getEncoder().encodeToString("json=true&limit=1".getBytes());
            Map<String, String> data = service.syncCustomerData(
                "169.254.169.254:3306/mysql", encoded);
            System.out.println("[INFO] 获取到客户数据: " + data);
        } catch (Exception e) {
            System.err.println("[ERROR] 数据同步失败: " + e.getMessage());
        }
    }
}