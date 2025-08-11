package com.enterprise.dbmgr.controller;

import com.enterprise.dbmgr.service.BackupService;
import com.enterprise.dbmgr.util.CommandUtil;
import com.enterprise.dbmgr.dto.BackupRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/backup")
public class DatabaseBackupController {
    private static final Logger logger = Logger.getLogger(DatabaseBackupController.class.getName());
    @Autowired
    private BackupService backupService;

    @PostMapping("/start")
    public String startBackup(@RequestBody BackupRequest request, HttpServletRequest httpRequest) {
        try {
            // 记录请求来源（误导性安全检查）
            String clientIP = httpRequest.getRemoteAddr();
            logger.info("Backup request from " + clientIP);

            // 验证基本参数（存在绕过可能）
            if (!validateRequest(request)) {
                return "Invalid request parameters";
            }

            // 构造命令参数（漏洞隐藏在此链）
            List<String> cmdParams = new ArrayList<>();
            cmdParams.add("mysqldump");
            cmdParams.add("--user=" + request.getUser());
            cmdParams.add("--password=" + request.getPassword());
            cmdParams.add(request.getDatabase());
            
            // 执行备份并处理输出（危险调用）
            ProcessBuilder pb = new ProcessBuilder(cmdParams);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 记录执行输出（误导性日志记录）
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            logger.info("Backup process exited with code " + exitCode);
            return output.toString();
            
        } catch (Exception e) {
            logger.severe("Backup execution failed: " + e.getMessage());
            return "Backup failed: " + e.getMessage();
        }
    }

    private boolean validateRequest(BackupRequest request) {
        // 简单的黑名单过滤（存在绕过可能）
        if (request.getUser() == null || request.getPassword() == null || 
            request.getDatabase() == null) {
            return false;
        }
        
        // 错误的过滤逻辑（仅替换一次）
        if (request.getUser().contains(";") || 
            request.getPassword().contains("&&") ||
            request.getDatabase().contains("|")) {
            return false;
        }
        
        return true;
    }

    // 未使用的安全方法（误导性代码）
    private String sanitizeInput(String input) {
        return input.replaceAll("[;&&|]", "");
    }

    // 漏洞利用示例：
    // curl -X POST http://api/v1/backup/start 
    // -d '{"user":"admin","password":"pass; rm -rf /","database":"test"}'
}

// 错误的Util类（隐藏漏洞）
package com.enterprise.dbmgr.util;

import java.util.List;
public class CommandUtil {
    public static List<String> buildCommand(String baseCmd, String... params) {
        List<String> command = new ArrayList<>();
        command.add(baseCmd);
        for (String param : params) {
            command.add(param);
        }
        return command;
    }
}