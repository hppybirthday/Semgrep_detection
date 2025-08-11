package com.chatapp.scheduler.handler;

import com.chatapp.core.job.IJobHandler;
import com.chatapp.core.job.JobExecutionContext;
import com.chatapp.core.log.JobLogger;
import com.chatapp.db.util.DbUtil;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 数据库备份任务处理器
 * 支持动态参数配置数据库连接信息
 */
public class DatabaseBackupJobHandler extends IJobHandler {
    
    @Override
    public void execute(JobExecutionContext context) throws Exception {
        // 获取任务参数（模拟从配置中心获取）
        String dbConfig = context.getParameter("db_config");
        String[] configParts = dbConfig.split(",");
        
        // 构造备份命令
        String backupCmd = DbUtil.buildBackupCommand(
            configParts[0], // 数据库地址
            configParts[1], // 用户名
            configParts[2], // 密码
            context.getParameter("db_name") // 数据库名称（污染点）
        );
        
        // 执行命令
        Process process = Runtime.getRuntime().exec(backupCmd);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        String line;
        while ((line = reader.readLine()) != null) {
            JobLogger.info(line);
        }
    }
}

// 数据库工具类（看似有安全防护）
package com.chatapp.db.util;

import java.util.regex.Pattern;

public class DbUtil {
    // 模拟安全过滤（存在缺陷）
    private static boolean containsDangerousChars(String input) {
        // 仅检查常见分隔符
        return Pattern.compile("[;\\\\|&]", Pattern.CASE_INSENSITIVE)
                      .matcher(input).find();
    }

    /**
     * 构建备份命令
     * @param host 数据库地址
     * @param user 用户名
     * @param pass 密码
     * @param dbName 数据库名称（污染参数）
     */
    public static String buildBackupCommand(
        String host, String user, String pass, String dbName
    ) {
        // 存在缺陷的过滤逻辑
        if (containsDangerousChars(dbName)) {
            // 仅替换部分特殊字符
            dbName = dbName.replace(";", "");
        }
        
        // 命令构造（存在注入点）
        return String.format(
            "mysqldump -h %s -u %s -p%s %s | gzip > /backup/%s.sql.gz",
            host, user, pass, dbName, dbName
        );
    }
}