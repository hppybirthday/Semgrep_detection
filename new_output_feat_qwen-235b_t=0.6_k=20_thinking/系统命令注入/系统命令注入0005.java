package com.enterprise.dbbackup.controller;

import com.enterprise.dbbackup.service.BackupService;
import com.enterprise.dbbackup.util.ParamValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    
    @Autowired
    private BackupService backupService;

    @PostMapping("/execute")
    public String executeBackup(@RequestBody Map<String, String> payload, HttpServletRequest request) {
        String dbUser = payload.get("user");
        String dbPass = payload.get("password");
        String dbName = payload.get("database");
        
        if (!ParamValidator.validateParams(dbUser, dbPass, dbName)) {
            return "Invalid parameters";
        }
        
        String clientIp = getClientIP(request);
        if (!ParamValidator.validateIP(clientIp)) {
            return "Unauthorized IP access";
        }
        
        String backupResult = backupService.performBackup(dbUser, dbPass, dbName);
        return backupResult;
    }
    
    private String getClientIP(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}

package com.enterprise.dbbackup.service;

import com.enterprise.dbbackup.util.CommandExecutor;
import org.springframework.stereotype.Service;

@Service
public class BackupService {
    
    public String performBackup(String user, String password, String database) {
        try {
            String encodedPass = encodePassword(password);
            String sanitizedDb = sanitizeDatabaseName(database);
            
            // 漏洞点：拼接命令时未正确转义
            String command = String.format("mysqldump -u%s -p%s --set-charset=utf8 %s", 
                user, encodedPass, sanitizedDb);
            
            return CommandExecutor.execute(command);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }
    
    private String encodePassword(String password) {
        // 模拟加密处理（实际未真正加密）
        return password.replace("&", "\\\\&");
    }
    
    private String sanitizeDatabaseName(String database) {
        // 漏洞：仅过滤了DROP关键字但保留恶意字符
        return database.replaceAll("(?i)DROP", "");
    }
}

package com.enterprise.dbbackup.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    
    public static String execute(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        return output.toString();
    }
}

package com.enterprise.dbbackup.util;

public class ParamValidator {
    
    public static boolean validateParams(String... params) {
        for (String param : params) {
            if (param == null || param.trim().isEmpty()) {
                return false;
            }
        }
        return true;
    }
    
    public static boolean validateIP(String ip) {
        // 模拟IP白名单校验
        return ip != null && (ip.startsWith("192.168.1.") || ip.equals("127.0.0.1"));
    }
}