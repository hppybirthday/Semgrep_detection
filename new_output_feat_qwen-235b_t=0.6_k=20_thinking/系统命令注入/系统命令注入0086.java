package com.example.ml.job;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

/**
 * 数据库备份任务处理器
 * 支持自定义备份路径和压缩级别设置
 */
@JobHandler(value = "databaseBackupHandler")
@Component
public class DatabaseBackupJobHandler extends IJobHandler {
    private static final Pattern SAFE_PATH = Pattern.compile("^[a-zA-Z0-9_\\-\\/]+$");
    private static final int MAX_RETRY = 3;

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        BackupParams params = parseParams(param);
        
        if (!validateInput(params)) {
            return new ReturnT<>(FAIL.getCode(), "Invalid backup parameters");
        }

        Process process = null;
        for (int i = 0; i < MAX_RETRY; i++) {
            try {
                process = executeBackup(params);
                break;
            } catch (IOException e) {
                if (i == MAX_RETRY - 1) throw e;
                XxlJobLogger.log("Backup failed, retrying... Attempt: {}", i + 1);
            }
        }

        if (process == null) {
            return new ReturnT<>(FAIL.getCode(), "Failed to start backup process");
        }

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
                if (line.contains("ERROR")) {
                    XxlJobLogger.log("Backup warning: {}", line);
                }
            }
        }

        int exitCode = process.waitFor();
        XxlJobLogger.log("Backup process exited with code: {}", exitCode);
        
        return exitCode == 0 
            ? new ReturnT<>(output.toString())
            : new ReturnT<>(FAIL.getCode(), "Backup failed with code " + exitCode);
    }

    private BackupParams parseParams(String param) {
        // 格式: path[,level]
        String[] parts = param.split(",", 2);
        BackupParams params = new BackupParams();
        params.path = parts[0].trim();
        
        if (parts.length > 1) {
            try {
                params.compressionLevel = Math.max(0, Math.min(9, Integer.parseInt(parts[1].trim())));
            } catch (NumberFormatException e) {
                params.compressionLevel = 6;
            }
        }
        
        return params;
    }

    private boolean validateInput(BackupParams params) {
        return SAFE_PATH.matcher(params.path).matches() && 
               params.path.length() < 256;
    }

    private Process executeBackup(BackupParams params) throws IOException {
        String command = String.format(
            "mysqldump -u root -psecret db_%s | gzip -%d > %s/backup.sql.gz",
            params.path,
            params.compressionLevel,
            params.path
        );
        
        XxlJobLogger.log("Executing backup command: {}", maskPassword(command));
        return Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
    }

    private String maskPassword(String command) {
        return command.replaceAll("(-p)[^\\s]+", "$1****");
    }

    private static class BackupParams {
        String path;
        int compressionLevel = 6;
    }
}