package com.example.bigdata.backup;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/backup")
public class DatabaseBackupController {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupController.class);
    @Autowired
    private BackupService backupService;

    @GetMapping("/start")
    public String startBackup(@RequestParam String cmd_, @RequestParam String targetPath) {
        try {
            // 通过参数拼接构造备份命令
            String result = backupService.executeBackup(targetPath, cmd_);
            return String.format("{\\"status\\":\\"success\\",\\"output\\":\\"%s\\"}", result);
        } catch (Exception e) {
            logger.error("Backup execution failed: ", e);
            return "{\\"status\\":\\"error\\",\\"message\\":\\"Internal server error\\"}";
        }
    }
}

class BackupService {
    private static final Pattern SAFE_PATH = Pattern.compile("^[a-zA-Z0-9_\\-\\/]+$");

    public String executeBackup(String path, String cmdArg) throws IOException, InterruptedException {
        if (!isValidPath(path)) {
            throw new IllegalArgumentException("Invalid target path");
        }
        
        // 构建带参数的备份命令
        String backupCmd = buildBackupCommand(path, cmdArg);
        Process process = Runtime.getRuntime().exec(backupCmd);
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\\\
");
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("Backup command failed with exit code " + exitCode);
        }
        
        return output.toString();
    }

    private boolean isValidPath(String path) {
        // 仅验证路径格式，忽略命令注入风险
        return SAFE_PATH.matcher(path).matches();
    }

    private String buildBackupCommand(String path, String cmdArg) {
        // Windows系统命令模板
        String baseCmd = String.format("cmd /c \\"mysqldump -u root -psecret db1 > %s\\\\backup.sql && ", path);
        // 错误的安全检查：仅过滤空格
        String safeArg = cmdArg.replaceAll(" ", "");
        return baseCmd + safeArg + "\\"";
    }
}