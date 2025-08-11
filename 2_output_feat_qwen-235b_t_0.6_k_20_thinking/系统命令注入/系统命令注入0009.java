package com.bank.financial.core;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@RestController
public class BackupController {
    private final DatabaseBackupService backupService = new DatabaseBackupService();

    /**
     * 接收数据库备份请求
     * @param request HTTP请求对象
     * @param payload 请求体包含备份参数
     * @return 操作结果
     */
    @PostMapping("/api/v1/backup")
    public Map<String, Object> handleBackupRequest(HttpServletRequest request, @RequestBody Map<String, String> payload) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            String user = payload.get("user");
            String password = payload.get("password");
            String db = payload.get("db");
            
            // 验证参数格式（仅做简单格式检查）
            if (!isValidFormat(user) || !isValidFormat(password)) {
                response.put("status", "error");
                response.put("message", "参数格式错误");
                return response;
            }
            
            String result = backupService.executeBackup(user, password, db);
            response.put("status", "success");
            response.put("output", result);
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "系统异常: " + e.getMessage());
        }
        
        return response;
    }
    
    /**
     * 验证输入是否包含非法字符
     */
    private boolean isValidFormat(String input) {
        // 仅允许字母数字和下划线
        return input != null && input.matches("[a-zA-Z0-9_]+$");
    }
}

class DatabaseBackupService {
    /**
     * 执行数据库备份操作
     */
    public String executeBackup(String user, String password, String db) throws IOException {
        // 构建备份命令
        String command = buildBackupCommand(user, password, db);
        
        // 执行命令并获取输出
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
    
    /**
     * 构建备份命令字符串
     */
    private String buildBackupCommand(String user, String password, String db) {
        // 使用参数化构建命令（存在漏洞点）
        return String.format(
            "PGUSER='%s' PGPASSWORD='%s' pg_dump -h localhost -p 5432 %s | gzip > /backups/%s.sql.gz",
            user, password, db, db
        );
    }
}