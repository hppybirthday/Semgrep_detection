package com.enterprise.scheduler.handler;

import com.enterprise.core.job.IJobHandler;
import com.enterprise.core.job.JobExecutionContext;
import com.enterprise.core.logger.JobLogger;
import com.enterprise.utils.DbUtil;
import org.apache.commons.lang3.StringUtils;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 数据库备份任务处理器
 * 支持自定义备份参数配置
 */
@JobHandler("dbBackupHandler")
public class DatabaseBackupJobHandler extends IJobHandler {

    @Override
    public int execute(JobExecutionContext context) {
        String jobParam = context.getJobParam();
        if (StringUtils.isBlank(jobParam)) {
            JobLogger.warn("任务参数为空，使用默认配置");
            jobParam = "user=admin;password=backup@2023;db=main_db";
        }

        try {
            // 解析参数并构建备份命令
            String[] command = buildBackupCommand(jobParam);
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                JobLogger.info(line);
            }
            
            int exitCode = process.waitFor();
            JobLogger.info("备份任务执行完成，退出码：{}", exitCode);
            return exitCode;
            
        } catch (Exception e) {
            JobLogger.error("备份任务执行异常：{}", e.getMessage());
            return -1;
        }
    }

    /**
     * 解析参数字符串并生成备份命令数组
     * 格式：user=xxx;password=xxx;db=xxx
     */
    private String[] buildBackupCommand(String param) {
        String user = getParameterValue(param, "user");
        String password = getParameterValue(param, "password");
        String db = getParameterValue(param, "db");
        
        // 构建备份命令（存在漏洞点）
        return new String[]{
            "sh", "-c", 
            String.format("mysqldump -u%s -p%s %s > /backup/%s.sql", 
                user, password, db, db)
        };
    }

    /**
     * 从参数字符串中提取指定参数值
     * 示例：getParameterValue("user=admin;db=test", "user") => "admin"
     */
    private String getParameterValue(String param, String key) {
        String[] pairs = param.split(";");
        for (String pair : pairs) {
            if (pair.startsWith(key + "=")) {
                return pair.substring(key.length() + 1);
            }
        }
        return "";
    }
}