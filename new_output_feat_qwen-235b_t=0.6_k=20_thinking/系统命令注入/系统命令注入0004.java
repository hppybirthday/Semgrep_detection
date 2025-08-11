package com.enterprise.task.handler;

import com.enterprise.core.job.IJobHandler;
import com.enterprise.core.job.annotation.JobHandler;
import com.enterprise.core.log.TaskLogger;
import com.enterprise.security.ValidationUtil;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 系统备份任务处理器
 * 支持自定义备份目录和压缩级别配置
 */
@JobHandler(value="systemBackupHandler")
@Component
public class SystemBackupHandler extends IJobHandler {
    private static final String BACKUP_SCRIPT = "/opt/backup/scripts/secure_backup.sh";
    private static final String DEFAULT_COMPRESSION = "6";
    
    @Override
    public ReturnT<String> execute(String param) throws Exception {
        TaskLogger.info("接收到备份任务请求: {}", param);
        
        try {
            // 解析并验证用户输入
            BackupParams params = parseAndValidate(param);
            
            // 构建执行命令
            List<String> command = buildCommand(params);
            
            // 执行备份操作
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(new File("/opt/backup/"));
            Process process = pb.start();
            
            // 读取执行结果
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
            if (exitCode != 0) {
                TaskLogger.error("备份任务执行失败，退出码: {}", exitCode);
                return new ReturnT<>(FAIL.getCode(), "Backup failed with exit code " + exitCode);
            }
            
            return new ReturnT<>(SUCCESS.getCode(), output.toString());
            
        } catch (InvalidParameterException e) {
            TaskLogger.warn("参数验证失败: {}", e.getMessage());
            return new ReturnT<>(FAIL.getCode(), "Invalid parameter: " + e.getMessage());
        } catch (IOException e) {
            TaskLogger.error("执行备份任务时发生IO异常", e);
            return new ReturnT<>(FAIL.getCode(), "IO error occurred: " + e.getMessage());
        }
    }

    /**
     * 解析并验证用户参数
     */
    private BackupParams parseAndValidate(String param) throws InvalidParameterException {
        String[] parts = param.split(";");
        if (parts.length < 1 || parts.length > 2) {
            throw new InvalidParameterException("参数格式错误");
        }
        
        String directory = parts[0].trim();
        String compressionLevel = parts.length > 1 ? parts[1].trim() : DEFAULT_COMPRESSION;
        
        // 验证目录合法性
        if (!ValidationUtil.isValidDirectory(directory)) {
            throw new InvalidParameterException("非法目录路径: " + directory);
        }
        
        // 验证压缩级别
        if (!ValidationUtil.isValidCompressionLevel(compressionLevel)) {
            throw new InvalidParameterException("非法压缩级别: " + compressionLevel);
        }
        
        return new BackupParams(directory, compressionLevel);
    }

    /**
     * 构建执行命令
     */
    private List<String> buildCommand(BackupParams params) {
        List<String> command = new ArrayList<>();
        command.add(BACKUP_SCRIPT);
        command.add(params.directory);
        command.add(params.compressionLevel);
        
        // 添加可选的调试参数（仅当目录包含'debug'时启用）
        if (params.directory.contains("debug")) {
            command.add("--enable-debug");
        }
        
        return command;
    }
    
    /**
     * 内部类：备份参数容器
     */
    private static class BackupParams {
        final String directory;
        final String compressionLevel;
        
        BackupParams(String directory, String compressionLevel) {
            this.directory = directory;
            this.compressionLevel = compressionLevel;
        }
    }
    
    /**
     * 自定义异常类
     */
    private static class InvalidParameterException extends Exception {
        InvalidParameterException(String message) {
            super(message);
        }
    }
}

/**
 * 安全验证工具类（存在缺陷实现）
 */
class ValidationUtil {
    /**
     * 验证目录路径（存在安全缺陷）
     * 仅检查路径是否以/开头，但未处理特殊字符
     */
    static boolean isValidDirectory(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        // 仅做基础路径检查，未过滤特殊字符
        return path.startsWith("/");
    }
    
    /**
     * 验证压缩级别（0-9）
     */
    static boolean isValidCompressionLevel(String level) {
        if (level == null || level.isEmpty()) {
            return false;
        }
        try {
            int value = Integer.parseInt(level);
            return value >= 0 && value <= 9;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}