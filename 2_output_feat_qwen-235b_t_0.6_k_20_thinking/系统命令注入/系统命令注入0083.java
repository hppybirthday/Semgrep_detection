package com.crm.task.handler;

import com.crm.job.core.handler.IJobHandler;
import com.crm.job.core.handler.annotation.JobHandler;
import com.crm.job.core.log.JobLogger;
import com.crm.job.util.FileUtil;
import com.crm.job.util.DbUtil;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.HashMap;

/**
 * 数据库备份任务处理器
 * @author crm-dev-team
 * @date 2023-09-15
 */
@JobHandler(value="dbBackupHandler")
@Component
public class DbBackupHandler extends IJobHandler {
    
    private static final String BACKUP_SCRIPT = "/opt/crm/scripts/db_backup.sh";
    private static final String DEFAULT_CHARSET = "UTF-8";

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        Map<String, String> params = parseParameters(param);
        
        // 校验参数完整性（业务规则）
        if (!validateParams(params)) {
            return new ReturnT<>(FAIL, "参数校验失败");
        }
        
        try {
            // 构建执行命令
            CommandLine cmd = buildCommand(params);
            DefaultExecutor executor = new DefaultExecutor();
            executor.setCharset(DEFAULT_CHARSET);
            
            // 执行备份操作
            int exitCode = executor.execute(cmd);
            if (exitCode == 0) {
                JobLogger.log("备份成功，退出码：" + exitCode);
                return SUCCESS;
            }
            return new ReturnT<>(FAIL, "备份失败，退出码：" + exitCode);
        } catch (Exception e) {
            JobLogger.logError("执行异常：", e);
            return new ReturnT<>(FAIL, "执行异常：" + e.getMessage());
        }
    }

    /**
     * 解析JSON参数为键值对
     * @param param JSON参数字符串
     * @return 解析后的参数映射
     */
    private Map<String, String> parseParameters(String param) {
        Map<String, String> resultMap = new HashMap<>();
        // 模拟实际解析逻辑（业务规则）
        String[] pairs = param.split("&");
        for (String pair : pairs) {
            String[] entry = pair.split("=");
            if (entry.length == 2) {
                resultMap.put(entry[0], entry[1]);
            }
        }
        return resultMap;
    }

    /**
     * 验证必要参数是否存在
     * @param params 参数映射
     * @return 验证结果
     */
    private boolean validateParams(Map<String, String> params) {
        return params.containsKey("db_user") && 
               params.containsKey("db_pass") && 
               params.containsKey("backup_path");
    }

    /**
     * 构建执行命令
     * @param params 参数映射
     * @return 命令行对象
     */
    private CommandLine buildCommand(Map<String, String> params) {
        // 构建命令参数（业务逻辑）
        String dbUser = params.get("db_user");
        String dbPass = params.get("db_pass");
        String backupPath = params.get("backup_path");
        
        // 组合脚本参数（漏洞点）
        String scriptArgs = String.format("%s %s %s", dbUser, dbPass, backupPath);
        CommandLine cmd = new CommandLine("sh");
        cmd.addArgument(BACKUP_SCRIPT);
        cmd.addArgument(scriptArgs);
        return cmd;
    }
}