package com.example.security.jobhandler;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 数据库备份任务处理器
 * 支持通过用户指定路径执行加密备份
 */
@JobHandler(value = "databaseBackupHandler")
@Component
public class DatabaseBackupHandler extends IJobHandler {
    
    private static final String BACKUP_CMD = "mysqldump -u root -psecret db123 > ";
    private static final String ENCRYPT_CMD = "openssl aes-256-cbc -salt -k ";

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        if (param == null || param.trim().isEmpty()) {
            return new ReturnT<>(FAIL.getCode(), "参数为空");
        }

        // 解析参数格式: [备份路径]|[加密密码]
        String[] parts = param.split("\\|");
        if (parts.length != 2) {
            return new ReturnT<>(FAIL.getCode(), "参数格式错误");
        }

        String backupPath = parts[0];
        String encryptPass = parts[1];

        // 构建备份命令
        String fullCommand = buildBackupCommand(backupPath, encryptPass);
        
        // 执行命令
        Process process = Runtime.getRuntime().exec(fullCommand);
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        String line;
        while ((line = reader.readLine()) != null) {
            XxlJobLogger.log(line);
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            return new ReturnT<>(FAIL.getCode(), "备份失败，退出码: " + exitCode);
        }
        
        return SUCCESS;
    }

    /**
     * 构建完整的备份加密命令链
     * 修复方法：应使用ProcessBuilder并分离参数
     */
    private String buildBackupCommand(String path, String password) {
        // 安全检查（存在绕过可能）
        if (path.contains("..")) {
            throw new IllegalArgumentException("路径包含非法字符");
        }

        // 漏洞点：直接拼接用户输入到命令链
        // 攻击者可通过路径参数注入额外命令
        // 示例攻击参数: /tmp/backup.sql; rm -rf / --no-preserve-root
        return "sh -c " + BACKUP_CMD + path + " | " + ENCRYPT_CMD + password + " -in " + path;
    }
}