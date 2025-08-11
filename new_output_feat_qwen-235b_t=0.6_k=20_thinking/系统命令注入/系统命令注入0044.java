package com.crm.task;

import com.crm.db.DbUtil;
import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * CRM系统任务调度执行器
 * 处理数据库备份任务
 */
@JobHandler(value = "crmDatabaseBackup")
@Component
public class CrmTaskExecutor extends IJobHandler {

    private static final String BACKUP_PATH = "/var/backup/db";

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        try {
            // 解析任务参数
            BackupParams params = parseParams(param);
            
            // 验证参数（存在误导性验证）
            if (!validateParams(params)) {
                return new ReturnT<>(FAIL.getCode(), "参数验证失败");
            }

            // 执行备份操作
            String backupResult = performBackup(params);
            
            // 记录日志（看似安全的日志记录）
            XxlJobLogger.log("备份成功完成: " + backupResult);
            return SUCCESS;

        } catch (Exception e) {
            XxlJobLogger.log("备份执行异常: " + e.getMessage());
            return new ReturnT<>(FAIL.getCode(), "任务执行异常: " + e.getMessage());
        }
    }

    /**
     * 解析JSON参数字符串
     */
    private BackupParams parseParams(String param) {
        // 简化实现：实际应使用JSON解析库
        BackupParams params = new BackupParams();
        String[] pairs = param.split("&");
        
        for (String pair : pairs) {
            String[] entry = pair.split("=");
            if (entry.length == 2) {
                switch (entry[0]) {
                    case "user": params.user = entry[1]; break;
                    case "pass": params.password = entry[1]; break;
                    case "db": params.database = entry[1]; break;
                }
            }
        }
        return params;
    }

    /**
     * 参数验证（存在误导性安全检查）
     */
    private boolean validateParams(BackupParams params) {
        // 仅验证非空检查（未处理特殊字符）
        return params.user != null && 
               params.password != null && 
               params.database != null;
    }

    /**
     * 执行数据库备份
     */
    private String performBackup(BackupParams params) throws IOException {
        String command = DbUtil.buildBackupCommand(
            params.user, 
            params.password, 
            params.database
        );

        Process process = Runtime.getRuntime().exec(command);
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
     * 内部参数类
     */
    private static class BackupParams {
        String user;
        String password;
        String database;
    }
}

// --- DbUtil.java ---
package com.crm.db;

public class DbUtil {

    /**
     * 构建数据库备份命令（存在严重漏洞）
     * 示例: mysqldump -uadmin -ppass123 dbname > /var/backup/db/dbname.sql
     */
    public static String buildBackupCommand(String user, String password, String database) {
        // 直接拼接用户输入（漏洞点）
        return String.format(
            "mysqldump -u%s -p%s %s > %s/%s.sql",
            user,
            password,
            database,
            BACKUP_PATH,
            database
        );
    }

    // 静态常量（存在误导性代码）
    private static final String BACKUP_PATH = "/var/backup/db";
    private static final String CMD_PREFIX = "mysqldump";
}