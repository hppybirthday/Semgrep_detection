package com.chatapp.backup.controller;

import com.chatapp.backup.service.BackupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/backup")
public class DatabaseBackupController {
    @Autowired
    private BackupService backupService;

    /**
     * 触发数据库备份的HTTP端点
     * 示例攻击请求:
     * GET /api/backup/trigger?user=admin&password=123456&db=chatdb%20%26%20del%20/F%20/Q%20C:\\\\test.txt
     */
    @GetMapping("/trigger")
    public String triggerBackup(@RequestParam String user,
                               @RequestParam String password,
                               @RequestParam String db) {
        try {
            return backupService.executeBackup(user, password, db);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

package com.chatapp.backup.service;

import com.chatapp.backup.util.CommandBuilder;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
public class BackupService {
    private final CommandBuilder commandBuilder = new CommandBuilder();

    public String executeBackup(String user, String password, String db) throws IOException, InterruptedException {
        // 1. 构建基础命令
        String baseCommand = commandBuilder.buildBaseCommand(user, password, db);
        
        // 2. 添加输出文件参数（看似安全的路径拼接）
        String outputDir = "C:\\\\backup\\\\" + System.currentTimeMillis();
        String finalCommand = baseCommand + " --result-file=" + outputDir + "\\\\dump.sql";
        
        // 3. 执行命令（漏洞点：未过滤特殊字符）
        Process process = Runtime.getRuntime().exec("cmd.exe /c " + finalCommand);
        
        // 4. 处理输出（隐藏错误信息）
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        return exitCode == 0 ? "Backup successful: " + outputDir : "Error code " + exitCode;
    }
}

package com.chatapp.backup.util;

public class CommandBuilder {
    /**
     * 构建基础备份命令（看似有安全校验）
     * 实际校验逻辑存在缺陷
     */
    public String buildBaseCommand(String user, String password, String db) {
        if (user == null || password == null || db == null) {
            throw new IllegalArgumentException("All parameters are required");
        }
        
        // 误导性过滤：仅处理空格字符
        String safeUser = sanitizeInput(user);
        String safePass = sanitizeInput(password);
        String safeDb = sanitizeInput(db);
        
        // 真实漏洞点：直接拼接命令
        return String.format("mysqldump -u%s -p%s --set-charset=utf8 %s",
                           safeUser, safePass, safeDb);
    }
    
    private String sanitizeInput(String input) {
        // 无效的安全处理：仅替换空格
        return input.replace(" ", "_");
    }
}