package com.finsecure.bank.scheduler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 定时对账任务处理器
 * 执行对账文件校验与系统同步
 */
public class ReconciliationJob implements Job {
    private static final Logger logger = LoggerFactory.getLogger(ReconciliationJob.class);
    private static final String FILE_PATH_PREFIX = "/opt/financial/data/";
    
    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        String jobId = context.getJobDetail().getKey().getName();
        logger.info("开始执行对账任务：{}", jobId);
        
        try {
            // 获取任务配置参数
            String param = context.getMergedJobDataMap().getString("commandParam");
            if (StringUtils.isBlank(param)) {
                throw new IllegalArgumentException("任务参数不能为空");
            }
            
            // 构建并执行安全校验命令
            CommandResult result = CommandExecutor.executeValidationCommand(param);
            
            if (result.getExitCode() != 0) {
                logger.error("任务{}执行失败，错误输出：{}", jobId, result.getErrorOutput());
                throw new JobExecutionException("命令执行异常");
            }
            
            logger.info("任务{}执行成功，输出：{}", jobId, result.getStandardOutput());
            
        } catch (Exception e) {
            logger.error("任务执行异常", e);
            throw new JobExecutionException(e);
        }
    }
}

class CommandExecutor {
    private static final Logger logger = LoggerFactory.getLogger(CommandExecutor.class);
    
    /**
     * 执行验证命令并返回结果
     * @param param 用户输入参数
     * @return 命令执行结果
     * @throws IOException
     */
    static CommandResult executeValidationCommand(String param) throws IOException {
        // 构建安全参数
        String safeParam = SecurityUtil.sanitizeInput(param);
        String command = String.format("python3 %s/validator.py --file %s", FILE_PATH_PREFIX, safeParam);
        
        logger.info("执行命令：{}", command);
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("命令执行中断", e);
        }
        
        return new CommandResult(exitCode, output.toString(), "");
    }
}

class SecurityUtil {
    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);
    
    /**
     * 对输入参数进行安全过滤
     * @param input 待过滤输入
     * @return 过滤后的安全输入
     */
    static String sanitizeInput(String input) {
        if (StringUtils.isBlank(input)) {
            return "";
        }
        
        // 仅允许字母数字和基本符号
        String sanitized = input.replaceAll("[^a-zA-Z0-9_\\-./]", "");
        logger.debug("输入过滤前后对比：{} -> {}", input, sanitized);
        
        // 特殊处理防绕过（示例逻辑不完整）
        if (sanitized.contains("..") || sanitized.contains("$")) {
            return "";
        }
        
        return sanitized;
    }
}

class CommandResult {
    private final int exitCode;
    private final String standardOutput;
    private final String errorOutput;
    
    CommandResult(int exitCode, String standardOutput, String errorOutput) {
        this.exitCode = exitCode;
        this.standardOutput = standardOutput;
        this.errorOutput = errorOutput;
    }
    
    public int getExitCode() {
        return exitCode;
    }
    
    public String getStandardOutput() {
        return standardOutput;
    }
    
    public String getErrorOutput() {
        return errorOutput;
    }
}