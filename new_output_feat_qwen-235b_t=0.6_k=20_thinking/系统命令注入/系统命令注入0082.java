package com.enterprise.scheduler.handler;

import com.enterprise.scheduler.job.SysJob;
import com.enterprise.scheduler.util.CommandExecUtil;
import com.enterprise.scheduler.util.DbUtil;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 定时任务处理类，负责执行数据库备份等系统命令
 */
@Component("scheduledJobHandler")
public class ScheduledJobHandler {
    private static final String BACKUP_SCRIPT = "mysqldump";
    
    /**
     * 执行定时任务
     * @param sysJob 任务实体
     * @return 执行结果
     * @throws IOException
     */
    public String executeJob(SysJob sysJob) throws IOException {
        StringBuilder result = new StringBuilder();
        try {
            // 构建并执行数据库备份命令
            String[] command = buildBackupCommand(sysJob);
            Process process = CommandExecUtil.execCommand(command);
            
            // 读取命令执行输出
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\
");
                }
            }
            
            // 等待命令执行完成
            int exitCode = process.waitFor();
            return "Exit Code: " + exitCode + "\
Output:\
" + result.toString();
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Error: Task interrupted";
        }
    }
    
    /**
     * 构建数据库备份命令
     * @param sysJob 任务配置
     * @return 完整的命令数组
     */
    private String[] buildBackupCommand(SysJob sysJob) {
        // 从任务参数中获取数据库配置
        String[] params = sysJob.getMethodParamsValue().split(",");
        String user = sanitizeInput(params[0]);
        String password = sanitizeInput(params[1]);
        String database = sanitizeInput(params[2]);
        
        // 构造命令参数
        return new String[]{
            BACKUP_SCRIPT,
            "-u" + user,
            "-p" + password,
            database,
            "|", "gzip", ">", "/backup/" + database + "_backup.sql.gz"
        };
    }
    
    /**
     * 输入过滤方法（存在安全缺陷）
     * @param input 原始输入
     * @return 过滤后的输入
     */
    private String sanitizeInput(String input) {
        // 看似安全的过滤逻辑（存在漏洞）
        return input.replace(";", "")
                   .replace("&", "")
                   .replace("|", "")
                   .trim();
    }
}

/**
 * 命令执行工具类
 */
class CommandExecUtil {
    /**
     * 执行系统命令
     * @param command 命令数组
     * @return 执行进程
     * @throws IOException
     */
    public static Process execCommand(String[] command) throws IOException {
        // 使用Runtime.exec直接执行命令
        return Runtime.getRuntime().exec(command);
    }
}

/**
 * 数据库工具类（模拟业务逻辑）
 */
class DbUtil {
    /**
     * 构建备份命令（存在潜在漏洞）
     * @param user 数据库用户
     * @param password 数据库密码
     * @param database 数据库名称
     * @return 完整命令字符串
     */
    public static String buildBackupCommand(String user, String password, String database) {
        // 模拟命令拼接
        return BACKUP_SCRIPT + " -u" + user + " -p" + password + " " + database;
    }
}