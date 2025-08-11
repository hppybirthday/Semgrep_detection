package com.example.mlplatform.job;

import com.example.mlplatform.util.JobLogger;
import com.example.mlplatform.util.ParamValidator;
import com.example.mlplatform.util.CommandExecutor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

/**
 * 机器学习模型训练任务处理器
 * 支持通过参数动态配置训练脚本路径和参数
 */
public class ModelTrainingJobHandler {
    
    private static final String TRAINING_SCRIPT = "/opt/ml/scripts/train.sh";
    private static final String DEFAULT_TIMEOUT = "3600";

    /**
     * 执行训练任务
     * @param rawParams 原始任务参数（格式：key1=value1;key2=value2）
     * @return 执行结果
     */
    public Map<String, Object> executeTrainingTask(String rawParams) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // 解析并验证参数
            Map<String, String> params = parseAndValidateParams(rawParams);
            
            // 构造执行命令
            String[] command = buildCommand(params);
            
            // 执行训练脚本
            String output = CommandExecutor.execute(command, Integer.parseInt(DEFAULT_TIMEOUT));
            
            result.put("status", "success");
            result.put("output", output);
            
        } catch (Exception e) {
            result.put("status", "error");
            result.put("error", e.getMessage());
            JobLogger.logError("训练任务执行失败: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * 解析并验证参数格式
     */
    private Map<String, String> parseAndValidateParams(String rawParams) {
        Map<String, String> params = new HashMap<>();
        
        if (rawParams == null || rawParams.isEmpty()) {
            return params;
        }
        
        // 按分号分割参数项
        for (String paramPair : rawParams.split(";")) {
            if (paramPair.contains("=")) {
                String[] parts = paramPair.split("=", 2);
                String key = parts[0].trim();
                String value = ParamValidator.sanitizeInput(parts[1].trim());
                params.put(key, value);
            }
        }
        
        return params;
    }

    /**
     * 构建训练命令数组
     */
    private String[] buildCommand(Map<String, String> params) {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append(TRAINING_SCRIPT);
        
        // 添加参数到命令
        for (Map.Entry<String, String> entry : params.entrySet()) {
            commandBuilder.append(String.format(" --%s=%s", entry.getKey(), entry.getValue()));
        }
        
        // 执行shell命令
        return new String[]{"sh", "-c", commandBuilder.toString()};
    }
}

/**
 * 参数安全处理工具类
 */
class ParamValidator {
    /**
     * 对输入参数进行基础过滤
     */
    public static String sanitizeInput(String input) {
        if (input == null) return "";
        
        // 过滤特殊字符（简单替换）
        return input.replaceAll("[;\\\\|&]", "");
    }
}

/**
 * 命令执行工具类
 */
class CommandExecutor {
    /**
     * 执行系统命令
     * @param command 命令数组
     * @param timeout 超时时间（秒）
     * @return 命令输出
     * @throws IOException
     * @throws InterruptedException
     */
    public static String execute(String[] command, int timeout) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        // 等待进程完成或超时
        boolean completed = process.waitFor(timeout, java.util.concurrent.TimeUnit.SECONDS);
        if (!completed) {
            process.destroyForcibly();
            throw new RuntimeException("命令执行超时");
        }
        
        // 读取输出
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
}