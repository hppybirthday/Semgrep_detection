package com.crm.task;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    private static final Logger logger = LoggerFactory.getLogger(TaskController.class);
    private final TaskSchedulerService taskScheduler = new TaskSchedulerService();

    @GetMapping("/execute")
    public String executeTask(@RequestParam String jobName, @RequestParam String param) {
        try {
            return taskScheduler.runScheduledTask(jobName, param);
        } catch (Exception e) {
            logger.error("Task execution failed: {}", e.getMessage());
            return "Task failed: " + e.getMessage();
        }
    }
}

class TaskSchedulerService {
    private final CommandExecutor executor = new CommandExecutor();

    public String runScheduledTask(String jobName, String param) throws Exception {
        List<String> command = buildCommand(jobName, param);
        return executor.executeCommand(command);
    }

    private List<String> buildCommand(String jobName, String param) {
        List<String> command = new ArrayList<>();
        
        // 模拟根据任务类型构造不同命令
        switch(jobName) {
            case "import_data":
                command.add("/opt/crm/scripts/import.sh");
                command.add("--path");
                // 漏洞点：未正确过滤参数中的特殊字符
                command.add(ParamSanitizer.sanitizePath(param));
                break;
            case "generate_report":
                command.add("/usr/bin/python3");
                command.add("/opt/crm/reports/generator.py");
                command.add("--output-dir");
                command.add(ParamSanitizer.sanitizePath(param));
                break;
            default:
                command.add("echo");
                command.add("Invalid task");
        }
        return command;
    }
}

class ParamSanitizer {
    // 看似安全的过滤函数（存在缺陷）
    static String sanitizePath(String input) {
        if (input == null || input.isEmpty()) {
            return "default_path";
        }
        
        // 仅过滤简单的分号攻击
        String sanitized = input.replace(";", "");
        
        // 深度漏洞点：允许特殊字符绕过
        // 例如：通过"&"替代分号实现命令拼接
        if (sanitized.contains("..") || sanitized.contains("/") || sanitized.contains("\\\\")) {
            throw new IllegalArgumentException("Invalid path format");
        }
        
        return sanitized;
    }
}

class CommandExecutor {
    String executeCommand(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().put("PATH", "/bin:/usr/bin:/opt/crm/scripts");
        
        Process process = pb.start();
        
        // 设置超时防止DOS攻击
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.destroy();
            throw new IOException("Command timeout");
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