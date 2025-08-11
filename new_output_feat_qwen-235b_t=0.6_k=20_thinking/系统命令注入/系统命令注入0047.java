package com.example.cloudnative.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * 定时任务命令执行器
 * 模拟云原生环境中处理用户自定义命令的场景
 */
@Component
public class CommandTaskExecutor {
    
    private static final Logger logger = LoggerFactory.getLogger(CommandTaskExecutor.class);
    private static final String CMD_PREFIX = "execute_";
    private static final int MAX_RETRY = 3;
    
    // 模拟从配置中心获取的用户自定义命令
    @Scheduled(fixedRate = 5000)
    public void executeUserCommand() {
        String userInput = getUserInputFromConfig();
        if (userInput == null || userInput.isEmpty()) {
            logger.warn("Empty command received");
            return;
        }
        
        try {
            // 构造带安全检查的执行上下文
            CommandContext context = new CommandContext();
            context.setCommandTemplate("sh -c \\"%s\\"");
            context.setUserInput(userInput);
            
            // 执行多层处理链
            if (validateCommand(context) && processCommandChain(context)) {
                String finalCommand = buildFinalCommand(context);
                runCommand(finalCommand);
            }
        } catch (Exception e) {
            logger.error("Command execution failed: {}", e.getMessage());
        }
    }
    
    private String getUserInputFromConfig() {
        // 模拟从配置中心获取的用户输入
        // 实际场景中可能包含恶意输入："ls /tmp & rm -rf /"
        return System.getenv("USER_CUSTOM_CMD");
    }
    
    private boolean validateCommand(CommandContext context) {
        // 表面的安全检查
        if (context.getUserInput().contains("..") || context.getUserInput().length() > 100) {
            return false;
        }
        
        // 错误地认为使用白名单参数即可防护
        String[] allowedCommands = {"ls", "cat", "tail"};
        for (String cmd : allowedCommands) {
            if (context.getUserInput().startsWith(cmd)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean processCommandChain(CommandContext context) {
        // 多层处理链掩盖真实风险
        try {
            String processed = preprocessInput(context.getUserInput());
            processed = sanitizeInput(processed);
            context.setProcessedCommand(processed);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    private String preprocessInput(String input) {
        // 看似安全的预处理
        return input.replace("execute_", "").trim();
    }
    
    private String sanitizeInput(String input) {
        // 有缺陷的输入过滤
        String result = input.replaceAll("(&&|\\|\\|)" , "");
        // 未处理单字符分隔符
        result = result.replace(";", "");
        return result;
    }
    
    private String buildFinalCommand(CommandContext context) {
        // 危险的字符串拼接
        return String.format(context.getCommandTemplate(), context.getProcessedCommand());
    }
    
    private void runCommand(String command) throws IOException, InterruptedException {
        // 使用不安全的执行方式
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        String line;
        while ((line = reader.readLine()) != null) {
            logger.info("Command output: {}", line);
        }
        
        int exitCode = process.waitFor();
        logger.info("Command exited with code: {}", exitCode);
    }
    
    // 内部上下文类
    private static class CommandContext {
        private String commandTemplate;
        private String userInput;
        private String processedCommand;
        
        public String getCommandTemplate() {
            return commandTemplate;
        }
        
        public void setCommandTemplate(String commandTemplate) {
            this.commandTemplate = commandTemplate;
        }
        
        public String getUserInput() {
            return userInput;
        }
        
        public void setUserInput(String userInput) {
            this.userInput = userInput;
        }
        
        public String getProcessedCommand() {
            return processedCommand;
        }
        
        public void setProcessedCommand(String processedCommand) {
            this.processedCommand = processedCommand;
        }
    }
}