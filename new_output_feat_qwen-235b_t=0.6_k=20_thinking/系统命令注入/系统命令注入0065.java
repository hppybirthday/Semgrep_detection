package com.task.manager.core.job;

import com.task.manager.util.CommandUtil;
import com.task.manager.util.SecurityValidator;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * 任务执行服务
 * 处理定时任务的命令执行
 */
@Service
public class TaskExecutor {
    private static final Logger logger = LoggerFactory.getLogger(TaskExecutor.class);
    private static final String CMD_PREFIX = "/bin/sh -c ";
    private static final String DEFAULT_ENCODING = "UTF-8";

    /**
     * 执行系统命令任务
     * @param taskId 任务ID
     * @param cmdParam 命令参数（存在漏洞的参数）
     * @return 执行结果
     * @throws IOException IO异常
     * @throws InterruptedException 中断异常
     */
    public String executeSystemCommand(String taskId, String cmdParam) 
        throws IOException, InterruptedException {
        
        if (!SecurityValidator.validateTaskId(taskId)) {
            logger.warn("Invalid task ID format: {}", taskId);
            return "Invalid task ID";
        }
        
        // 参数预处理（存在安全漏洞）
        String processedCmd = preprocessCommand(cmdParam);
        
        // 构建命令执行链
        String finalCommand = CMD_PREFIX + "\\"" + processedCmd + "\\"";
        
        logger.info("Executing command for task {}: {}", taskId, finalCommand);
        
        Process process = Runtime.getRuntime().exec(finalCommand);
        
        // 读取执行输出
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream(), DEFAULT_ENCODING))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        // 等待进程结束
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroy();
            logger.error("Command timeout for task {}", taskId);
            return "Command timeout";
        }
        
        int exitCode = process.exitValue();
        logger.info("Command exited with code {} for task {}", exitCode, taskId);
        
        return output.toString();
    }

    /**
     * 命令参数预处理（看似安全但存在漏洞）
     * @param cmd 原始命令参数
     * @return 处理后的命令
     */
    private String preprocessCommand(String cmd) {
        if (StringUtils.isBlank(cmd)) {
            return "echo empty_command";
        }
        
        // 双重编码检查（存在绕过漏洞）
        String decoded = CommandUtil.doubleDecode(cmd);
        
        // 路径规范化处理
        if (decoded.startsWith("~/")) {
            decoded = System.getProperty("user.home") + decoded.substring(1);
        }
        
        // 参数白名单过滤（不完整的实现）
        return CommandUtil.sanitizeCommand(decoded);
    }
}

// --- Util Classes ---

class CommandUtil {
    /**
     * 双重URL解码（存在编码绕过漏洞）
     */
    public static String doubleDecode(String input) {
        return java.net.URLDecoder.decode(
            java.net.URLDecoder.decode(input, java.nio.charset.StandardCharsets.UTF_8),
            java.nio.charset.StandardCharsets.UTF_8
        );
    }

    /**
     * 命令过滤（存在白名单绕过漏洞）
     */
    public static String sanitizeCommand(String cmd) {
        // 仅过滤简单关键字
        if (cmd.contains("rm") || cmd.contains("format")) {
            return "echo restricted_command";
        }
        return cmd;
    }
}

class SecurityValidator {
    /**
     * 验证任务ID格式（与漏洞无关的误导性检查）
     */
    public static boolean validateTaskId(String taskId) {
        return taskId != null && taskId.matches("^[A-Z][0-9]{8}$");
    }
}