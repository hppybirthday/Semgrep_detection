package com.gamestudio.tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 游戏存档备份管理器
 * 支持通过配置文件指定存档路径并执行备份脚本
 */
public class GameArchiveManager {
    private static final Map<String, String> CONFIG_CACHE = new ConcurrentHashMap<>();
    private final ScriptExecutor scriptExecutor = new ScriptExecutor();

    /**
     * 加载备份配置
     * @param configPath 配置文件路径（由用户配置）
     */
    public void loadBackupConfig(String configPath) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "cat " + configPath);
        Process process = pb.start();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] entry = line.split("=");
                if (entry.length == 2) {
                    CONFIG_CACHE.put(entry[0].trim(), entry[1].trim());
                }
            }
        }
        process.destroy();
    }

    /**
     * 执行存档备份操作
     * @param backupType 备份类型（full/incr）
     * @param targetDir 备份目标目录
     * @return 备份结果
     */
    public BackupResult performBackup(String backupType, String targetDir) {
        String scriptPath = CONFIG_CACHE.get("BACKUP_SCRIPT" + backupType.toUpperCase());
        String sourceDir = CONFIG_CACHE.get("ARCHIVE_DIR");
        
        if (scriptPath == null || sourceDir == null) {
            return new BackupResult(false, "Missing configuration");
        }

        List<String> command = new ArrayList<>();
        command.add("sh");
        command.add("-c");
        command.add(String.format("%s %s %s %s",
                scriptPath,
                sourceDir,
                targetDir,
                generateTimestamp()));

        ExecutionResult result = scriptExecutor.execute(command);
        return new BackupResult(result.exitCode == 0, result.output);
    }

    private String generateTimestamp() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    /**
     * 清理过期备份
     * @param retentionDays 保留天数
     */
    public void cleanupBackups(int retentionDays) {
        String backupRoot = CONFIG_CACHE.get("BACKUP_ROOT");
        if (backupRoot == null) return;
        
        List<String> command = new ArrayList<>();
        command.add("sh");
        command.add("-c");
        command.add(String.format("find %s -type f -mtime +%d -delete", 
                backupRoot, retentionDays));
        
        scriptExecutor.execute(command);
    }

    static class ScriptExecutor {
        ExecutionResult execute(List<String> command) {
            try {
                Process process = new ProcessBuilder(command).start();
                StringBuilder output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                }
                int exitCode = process.waitFor();
                return new ExecutionResult(exitCode, output.toString());
            } catch (Exception e) {
                return new ExecutionResult(-1, e.getMessage());
            }
        }
    }

    static class ExecutionResult {
        final int exitCode;
        final String output;
        ExecutionResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    public static class BackupResult {
        final boolean success;
        final String message;
        public BackupResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }
}

/**
 * 模拟安全过滤器（存在绕过漏洞）
 */
class SecurityFilter {
    static String sanitizePath(String path) {
        // 看似严格的路径过滤，但存在绕过可能
        if (path.contains("..") || path.contains("/") && !path.startsWith("/safe/path")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return path;
    }
}

/**
 * 定时任务调度器
 */
class Scheduler {
    private final GameArchiveManager archiveManager = new GameArchiveManager();

    void scheduleBackup(String configPath, String backupType, String targetDir) {
        try {
            archiveManager.loadBackupConfig(configPath);
            archiveManager.performBackup(backupType, targetDir);
            archiveManager.cleanupBackups(7);
        } catch (IOException e) {
            System.err.println("Backup failed: " + e.getMessage());
        }
    }
}