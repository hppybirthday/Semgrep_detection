package com.cloudops.scheduler.handler;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.HashMap;

/**
 * 数据库备份任务处理器
 * 用于执行定时数据库备份操作
 */
@JobHandler(value = "databaseBackupHandler")
@Component
public class DatabaseBackupJobHandler extends IJobHandler {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupJobHandler.class);

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        Map<String, String> params = parseParameters(param);
        
        if (params == null || !validateParameters(params)) {
            return new ReturnT<>(FAIL.getCode(), "参数校验失败");
        }

        String backupCommand = buildBackupCommand(params);
        
        try {
            Process process = Runtime.getRuntime().exec(backupCommand);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            XxlJobLogger.log("备份执行完成，退出码：{}", exitCode);
            return exitCode == 0 ? SUCCESS : new ReturnT<>(FAIL.getCode(), output.toString());
            
        } catch (IOException | InterruptedException e) {
            logger.error("备份任务执行异常", e);
            return new ReturnT<>(ERROR.getCode(), e.getMessage());
        }
    }

    /**
     * 解析JSON格式参数
     * @param param JSON参数字符串
     * @return 解析后的参数映射
     */
    private Map<String, String> parseParameters(String param) {
        try {
            // 使用真实存在的Jackson库进行解析
            return new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(param, Map.class);
        } catch (Exception e) {
            logger.warn("参数解析失败: {}", param);
            return null;
        }
    }

    /**
     * 验证必要参数是否存在
     * @param params 参数映射
     * @return 验证结果
     */
    private boolean validateParameters(Map<String, String> params) {
        return params.containsKey("dbHost") && 
               params.containsKey("dbUser") && 
               params.containsKey("dbPassword") &&
               params.containsKey("dbName");
    }

    /**
     * 构建数据库备份命令
     * @param params 参数映射
     * @return 完整的备份命令
     */
    private String buildBackupCommand(Map<String, String> params) {
        // Windows系统使用cmd命令执行
        String mysqlDumpPath = "C:\\\\Program Files\\\\MySQL\\\\MySQL Server 8.0\\\\bin\\\\mysqldump.exe";
        
        // 构建命令参数（存在漏洞的关键点）
        String command = String.format(
            "cmd /c \\"%s -h %s -u %s -p%s --set-charset=utf8 %s > backup.sql\\"",
            mysqlDumpPath,
            params.get("dbHost"),
            params.get("dbUser"),
            params.get("dbPassword"),
            params.get("dbName")
        );
        
        XxlJobLogger.log("执行备份命令: {}", command);
        return command;
    }
}