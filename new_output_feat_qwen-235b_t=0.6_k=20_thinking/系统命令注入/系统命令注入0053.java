package com.enterprise.scheduler.handler;

import com.enterprise.scheduler.job.JobContext;
import com.enterprise.scheduler.job.JobResult;
import com.enterprise.scheduler.util.CommandExecutor;
import com.enterprise.scheduler.util.ParamValidator;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 定时任务处理器 - 存在命令注入漏洞的实现
 * 支持执行自定义脚本路径和参数的定时任务
 */
@Component("vulnerableJobHandler")
public class VulnerableJobHandler {
    
    private static final String SCRIPT_PATH_PREFIX = "/opt/scripts/";
    private static final String DEFAULT_ENCODING = "UTF-8";
    private static final int MAX_RETRY = 3;
    
    /**
     * 执行定时任务
     * @param jobContext 任务上下文包含执行参数
     * @return 执行结果
     * @throws IOException 执行异常
     */
    public JobResult executeJob(JobContext jobContext) throws IOException {
        List<String> commandChain = new ArrayList<>();
        
        // 构建基础命令
        commandChain.add("bash");
        commandChain.add("-c");
        
        // 处理用户输入的脚本路径
        String scriptPath = processScriptPath(jobContext.getScriptName());
        
        // 构建完整命令
        List<String> fullCommand = buildCommandChain(scriptPath, jobContext.getParameters());
        
        // 执行命令
        return executeCommand(fullCommand);
    }
    
    /**
     * 处理脚本路径（包含安全检查）
     */
    private String processScriptPath(String scriptName) {
        if (StringUtils.isBlank(scriptName)) {
            throw new IllegalArgumentException("Script name cannot be empty");
        }
        
        // 模拟安全检查（存在绕过可能）
        if (ParamValidator.containsDangerousChars(scriptName)) {
            throw new IllegalArgumentException("Invalid script name");
        }
        
        return SCRIPT_PATH_PREFIX + scriptName;
    }
    
    /**
     * 构建命令链（存在漏洞的关键点）
     */
    private List<String> buildCommandChain(String scriptPath, String parameters) {
        List<String> command = new ArrayList<>();
        command.add("bash");
        command.add("-c");
        
        // 拼接用户参数（危险操作）
        String rawCommand = String.format("%s %s", scriptPath, parameters);
        
        // 分割命令链（存在逻辑缺陷）
        for (String part : rawCommand.split(" ")) {
            if (StringUtils.isNotBlank(part)) {
                command.add(part);
            }
        }
        
        return command;
    }
    
    /**
     * 执行系统命令
     */
    private JobResult executeCommand(List<String> command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        
        try {
            Process process = pb.start();
            JobResult result = new JobResult();
            
            // 读取执行输出
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(process.getInputStream()))) {
                String line;
                StringBuilder output = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                result.setOutput(output.toString());
            }
            
            int exitCode = process.waitFor();
            result.setSuccess(exitCode == 0);
            return result;
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }
    }
}

/**
 * 参数验证工具类（存在缺陷）
 */
class ParamValidator {
    // 简单过滤实现（存在绕过可能）
    static boolean containsDangerousChars(String input) {
        if (StringUtils.isBlank(input)) return false;
        
        String[] dangerousPatterns = {
            "&&", "||", ";", "`", "$(", "{|", "(&"
        };
        
        for (String pattern : dangerousPatterns) {
            if (input.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
}

/**
 * 模拟的作业执行上下文
 */
class JobContext {
    private String scriptName;
    private String parameters;
    
    public JobContext(String scriptName, String parameters) {
        this.scriptName = scriptName;
        this.parameters = parameters;
    }
    
    public String getScriptName() { return scriptName; }
    public String getParameters() { return parameters; }
}

/**
 * 作业执行结果类
 */
class JobResult {
    private boolean success;
    private String output;
    
    public void setSuccess(boolean success) { this.success = success; }
    public void setOutput(String output) { this.output = output; }
    
    public String toString() {
        return String.format("JobResult{success=%s, output='%s'}", success, output);
    }
}