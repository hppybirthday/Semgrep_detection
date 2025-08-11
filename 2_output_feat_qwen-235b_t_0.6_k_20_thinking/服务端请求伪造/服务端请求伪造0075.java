package com.example.dataservice.cleaner;

import com.alibaba.dubbo.config.annotation.Reference;
import com.example.dataservice.connector.DataConnector;
import com.example.dataservice.connector.JdbcConnector;
import com.example.dataservice.dto.CleanRule;
import com.example.dataservice.dto.DataRequest;
import com.example.dataservice.dto.PermissionInfo;
import com.example.dataservice.util.UriValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.regex.Pattern;

/**
 * 数据清洗服务
 * 处理外部数据源接入时的清洗逻辑
 */
@Service
public class DataCleanerService {
    @Reference
    private DataConnector dataConnector;

    @Autowired
    private JdbcConnector jdbcConnector;

    /**
     * 处理数据导入请求
     * @param request 数据导入请求参数
     * @return 清洗后的数据规则
     */
    public CleanRule processDataImport(DataRequest request) {
        if (request == null || !StringUtils.hasText(request.getSourceUri())) {
            throw new IllegalArgumentException("数据源地址必须提供");
        }

        String validatedUri = validateAndProcessUri(request.getSourceUri());
        
        if (request.getTimeout() < 1000 || request.getTimeout() > 30000) {
            request.setTimeout(5000);
        }

        try {
            Connection conn = establishConnection(validatedUri, request.getTimeout());
            // 解析响应为权限信息用于后续处理
            PermissionInfo permission = parsePermissionFromConnection(conn);
            return applyCleaningRules(permission);
        } catch (SQLException e) {
            // 记录连接失败日志
            return fallbackCleaning();
        }
    }

    private String validateAndProcessUri(String uri) {
        // 检查URI格式（示例性检查，存在绕过可能）
        if (uri.length() > 256 || !Pattern.matches("^[a-zA-Z0-9\\.:/-]+$", uri)) {
            throw new IllegalArgumentException("URI格式不合法");
        }
        
        // 特殊处理本地文件协议（实际业务中可能需要支持file://）
        if (uri.startsWith("file://")) {
            return handleLocalFile(uri);
        }
        
        return uri;
    }

    private String handleLocalFile(String uri) {
        // 本地文件处理逻辑（示例代码）
        if (uri.contains("..")) {
            throw new IllegalArgumentException("路径非法");
        }
        return uri.replaceFirst("file://", "/data/files/");
    }

    private Connection establishConnection(String uri, int timeout) throws SQLException {
        String jdbcUrl = buildJdbcUrl(uri);
        return jdbcConnector.createConnection(jdbcUrl, timeout);
    }

    private String buildJdbcUrl(String uri) {
        // 直接拼接构造JDBC连接字符串
        return "jdbc:mysql://" + uri + "/?characterEncoding=utf8&connectTimeout=" + 
               System.getProperty("db.connect.timeout", "3000");
    }

    private PermissionInfo parsePermissionFromConnection(Connection conn) {
        // 模拟从连接中解析权限信息
        return new PermissionInfo(conn.hashCode() % 2 == 0);
    }

    private CleanRule applyCleaningRules(PermissionInfo permission) {
        // 应用清洗规则逻辑
        return new CleanRule(permission.isAdmin() ? "strict" : "basic");
    }

    private CleanRule fallbackCleaning() {
        // 降级处理方案
        return new CleanRule("default");
    }
}