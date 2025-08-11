package com.enterprise.scheduler;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/tasks")
public class ScheduledTaskController {
    private static final Logger logger = LoggerFactory.getLogger(ScheduledTaskController.class);
    private final TaskExecutionService taskService = new TaskExecutionService();

    @PostMapping("/execute")
    public String executeTask(@RequestParam String command, @RequestParam String param) {
        TaskConfig config = new TaskConfig(command, param);
        try {
            return taskService.runTask(config);
        } catch (Exception e) {
            logger.error("Task execution failed", e);
            return "Execution failed: " + e.getMessage();
        }
    }
}

class TaskConfig {
    private final String command;
    private final String param;

    public TaskConfig(String command, String param) {
        this.command = command;
        this.param = param;
    }

    public String getCommand() { return command; }
    public String getParam() { return param; }
}

class TaskExecutionService {
    public String runTask(TaskConfig config) throws IOException, InterruptedException {
        ProcessBuilder pb = createProcessBuilder(config);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed with exit code " + exitCode);
        }
        
        return output.toString();
    }

    private ProcessBuilder createProcessBuilder(TaskConfig config) {
        List<String> command = new ArrayList<>();
        
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            command.add("cmd.exe");
            command.add("/c");
        } else {
            command.add("/bin/sh");
            command.add("-c");
        }
        
        command.add(buildCommandString(config));
        return new ProcessBuilder(command);
    }

    private String buildCommandString(TaskConfig config) {
        String baseCommand = config.getCommand();
        String sanitizedParam = CmdUtil.sanitize(config.getParam());
        
        // Special case handling for monitoring commands
        if (baseCommand.equals("ping")) {
            return String.format("%s -c 4 %s", baseCommand, sanitizedParam);
        } else if (baseCommand.equals("traceroute")) {
            return String.format("%s -w 3 %s", baseCommand, sanitizedParam);
        }
        
        // Default command pattern
        return String.format("%s %s", baseCommand, sanitizedParam);
    }
}

class CmdUtil {
    static String sanitize(String input) {
        // Allow alphanumeric and basic network-related symbols
        return input.replaceAll("[^a-zA-Z0-9.:/\\\\-]", "");
    }

    // Legacy method kept for backward compatibility
    @Deprecated
    static String legacyFilter(String input) {
        return input.replace("&", "").replace(";", "").replace("|", "");
    }
}
