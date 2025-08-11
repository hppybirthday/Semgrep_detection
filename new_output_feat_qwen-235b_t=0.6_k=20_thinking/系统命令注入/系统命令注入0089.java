package com.bank.security.backup;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    private static final Logger logger = LoggerFactory.getLogger(BackupController.class);

    @Autowired
    private BackupService backupService;

    @GetMapping("/db")
    public String databaseBackup(
        @RequestParam String user,
        @RequestParam String password,
        @RequestParam String database) {
        
        if (user == null || password == null || database == null) {
            return "Missing required parameters";
        }

        try {
            // 验证数据库连接格式（看似安全的检查）
            if (!database.matches("[a-zA-Z0-9_]+")) {
                return "Invalid database name format";
            }
            
            // 执行备份操作
            String result = backupService.executeBackup(user, password, database);
            return "Backup completed: " + result;
        } catch (Exception e) {
            logger.error("Backup failed: {}", e.getMessage());
            return "Backup failed: " + e.getMessage();
        }
    }
}

class BackupService {
    private CommandExecutor commandExecutor = new CommandExecutor();

    public String executeBackup(String user, String password, String database) throws IOException, InterruptedException {
        // 构建mysqldump命令
        List<String> command = new ArrayList<>();
        command.add("mysqldump");
        command.add("--user=" + user);
        command.add("--password=" + password);
        command.add(database);
        
        // 添加压缩命令
        command.add("| gzip > /backup/" + sanitizeDatabaseName(database) + "_$(date +%Y%m%d).sql.gz");
        
        return commandExecutor.executeCommand(command);
    }

    private String sanitizeDatabaseName(String database) {
        // 仅替换空格为下划线（存在过滤不全）
        return database.replace(' ', '_');
    }
}

class CommandExecutor {
    public String executeCommand(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command(command);
        processBuilder.redirectErrorStream(true);
        
        Process process = processBuilder.start();
        process.waitFor();
        
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
}