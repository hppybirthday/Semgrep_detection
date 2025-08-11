package com.cloudnative.backup.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    
    @Autowired
    private DatabaseBackupService backupService;

    /**
     * 触发数据库备份操作
     * @param dbName 数据库名称
     * @param format 备份格式（sql/tar.gz）
     * @return 操作结果
     */
    @GetMapping("/db")
    public String backupDatabase(@RequestParam String dbName, 
                                @RequestParam(required = false) String format) {
        try {
            // 调用备份服务执行操作
            return backupService.executeBackup(dbName, format);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

@Service
class DatabaseBackupService {
    
    private static final Pattern SAFE_NAME = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");
    private final CommandExecutor executor = new CommandExecutor();

    /**
     * 执行数据库备份逻辑
     * @param dbName 原始数据库名称
     * @param format 备份格式
     * @return 执行输出
     * @throws IOException 执行异常
     */
    public String executeBackup(String dbName, String format) throws IOException {
        // 第一层过滤：仅允许特定字符集
        if (!SAFE_NAME.matcher(dbName).matches()) {
            throw new IllegalArgumentException("Invalid database name");
        }
        
        // 构造备份参数
        List<String> params = new ArrayList<>();
        params.add("--dbname=" + dbName);
        
        if (format != null && format.equals("tar.gz")) {
            params.add("--format=tar.gz");
        } else {
            params.add("--format=sql");
        }
        
        // 调用命令执行器
        return executor.runBackupCommand(params);
    }
}

class CommandExecutor {
    
    /**
     * 执行实际的备份命令
     * @param params 命令参数列表
     * @return 命令输出
     * @throws IOException 执行异常
     */
    String runBackupCommand(List<String> params) throws IOException {
        // 构建完整命令字符串
        String command = buildCommand(params);
        
        // 使用ProcessBuilder执行命令
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // 读取执行输出
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
     * 构建完整的备份命令
     * @param params 参数列表
     * @return 完整命令字符串
     */
    private String buildCommand(List<String> params) {
        // 模拟复杂业务逻辑中的字符串拼接
        StringBuilder cmd = new StringBuilder("/opt/dbtools/backup.sh");
        
        // 添加全局参数
        cmd.append(" --timeout=300");
        
        // 拼接用户参数
        for (String param : params) {
            cmd.append(" ").append(param);
        }
        
        // 添加日志参数
        cmd.append(" >> /var/log/dbbackup.log 2>&1");
        
        return cmd.toString();
    }
}