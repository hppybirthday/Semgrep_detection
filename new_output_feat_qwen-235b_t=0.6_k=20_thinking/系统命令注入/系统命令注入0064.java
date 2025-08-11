package com.chatapp.scheduler;

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

@Component
public class MessageTaskHandler implements Job {
    @Autowired
    private CommandExecutor commandExecutor;

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        String taskType = context.getMergedJobDataMap().getString("taskType");
        String userParam = context.getMergedJobDataMap().getString("userInput");
        
        try {
            // 构造命令参数
            String[] params = new String[]{"-u", userParam, "--type", taskType};
            List<String> filtered = InputSanitizer.sanitize(params);
            
            // 执行安全检查
            if (SecurityFilter.validateInput(filtered)) {
                String result = commandExecutor.executeCommand("/opt/chatapp/bin/msg_processor", filtered);
                context.setResult(result);
            }
        } catch (Exception e) {
            throw new JobExecutionException("Task failed: " + e.getMessage());
        }
    }
}

class CommandExecutor {
    public String executeCommand(String commandPath, List<String> params) throws IOException {
        ProcessBuilder builder = new ProcessBuilder();
        builder.command(constructCommand(commandPath, params));
        builder.redirectErrorStream(true);
        
        try {
            Process process = builder.start();
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
        } catch (IOException e) {
            throw new IOException("Command execution failed: " + e.getMessage());
        }
    }

    private String[] constructCommand(String commandPath, List<String> params) {
        String[] cmdArray = new String[params.size() + 1];
        cmdArray[0] = commandPath;
        for (int i = 0; i < params.size(); i++) {
            cmdArray[i + 1] = params.get(i);
        }
        return cmdArray;
    }
}

class InputSanitizer {
    public static List<String> sanitize(String[] params) {
        // 简单的输入过滤（存在绕过可能）
        for (int i = 0; i < params.length; i++) {
            params[i] = params[i].replaceAll("[;\\\\|&]", "");
        }
        return List.of(params);
    }
}

class SecurityFilter {
    public static boolean validateInput(List<String> input) {
        // 检查是否包含危险字符
        for (String param : input) {
            if (param.contains("rm") || param.contains("format")) {
                return false;
            }
        }
        return true;
    }
}