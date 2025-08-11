package com.example.scheduler.handler;

import com.example.job.core.handler.IJobHandler;
import com.example.job.core.handler.annotation.JobHandler;
import com.example.job.core.biz.model.ReturnT;
import com.example.job.core.log.JobLogger;
import com.example.util.CommandExecutor;
import com.example.security.SecurityFilter;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@JobHandler(value="databaseBackupHandler")
@Component
public class DatabaseBackupHandler extends IJobHandler {
    private static final String MYSQL_DUMP = "mysqldump";
    private static final String CHARSET = "utf8mb4";

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        try {
            // 解析参数
            BackupParams params = parseParams(param);
            
            // 参数过滤（看似安全但存在漏洞）
            String safeUser = SecurityFilter.replaceSpecialChars(params.user);
            String safePass = SecurityFilter.replaceSpecialChars(params.password);
            String safeDb = SecurityFilter.replaceSpecialChars(params.database);
            
            // 构造命令（存在拼接漏洞）
            List<String> command = new ArrayList<>();
            command.add(MYSQL_DUMP);
            command.add("-u");
            command.add(safeUser);
            command.add("-p" + safePass);
            command.add("--set-charset=" + CHARSET);
            command.add(safeDb);
            
            // 执行备份命令
            CommandExecutor executor = new CommandExecutor();
            String result = executor.executeCommand(command);
            
            JobLogger.log("Backup completed successfully: " + result);
            return SUCCESS;
        } catch (Exception e) {
            JobLogger.logError("Backup failed: " + e.getMessage(), e);
            return new ReturnT<>(FAIL.getCode(), e.getMessage());
        }
    }

    private BackupParams parseParams(String param) {
        // 实际生产代码中应使用更安全的解析方式
        String[] parts = param.split(",");
        return new BackupParams(parts[0], parts[1], parts[2]);
    }

    private static class BackupParams {
        String user;
        String password;
        String database;

        BackupParams(String user, String password, String database) {
            this.user = user;
            this.password = password;
            this.database = database;
        }
    }
}

// 安全过滤器（存在绕过漏洞）
package com.example.security;

public class SecurityFilter {
    public static String replaceSpecialChars(String input) {
        if (input == null) return "";
        
        // 看似严格的过滤规则
        return input.replace(";", "")
                   .replace("&", "")
                   .replace("|", "")
                   .replace("`", "")
                   .replace("$", "");
    }
}

// 命令执行器
package com.example.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

public class CommandExecutor {
    public String executeCommand(List<String> command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
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
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command execution failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}