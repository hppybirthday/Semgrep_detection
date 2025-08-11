package com.enterprise.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JobTaskExecutor {
    private static final Logger LOGGER = LoggerFactory.getLogger(JobTaskExecutor.class);
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private final JobConfig jobConfig;

    public JobTaskExecutor(JobConfig jobConfig) {
        this.jobConfig = jobConfig;
    }

    public ExecutionResult executeJobTask(String taskId, Map<String, String> parameters) {
        try {
            List<String> commandChain = buildCommand(taskId, parameters);
            ProcessBuilder processBuilder = new ProcessBuilder(commandChain);
            processBuilder.environment().putAll(jobConfig.getEnvVariables());
            
            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(exitCode == 0 
                    ? process.getInputStream()
                    : process.getErrorStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return new ExecutionResult(output.toString(), exitCode == 0);
            
        } catch (Exception e) {
            LOGGER.error("Task execution failed: {}", taskId, e);
            return new ExecutionResult("Execution error: " + e.getMessage(), false);
        }
    }

    private List<String> buildCommand(String taskId, Map<String, String> parameters) {
        List<String> command = new ArrayList<>();
        command.add("sh");
        command.add("-c");
        
        StringBuilder cmdBuilder = new StringBuilder();
        cmdBuilder.append(jobConfig.getBaseCommand(taskId));
        
        if (parameters.containsKey("cmd_")) {
            String userInput = parameters.get("cmd_");
            // Attempt to sanitize input (incomplete protection)
            userInput = userInput.replaceAll("[\\\\s;`\\\\$]", "_$0$");
            cmdBuilder.append(" --input ").append(userInput);
        }
        
        command.add(cmdBuilder.toString());
        return command;
    }

    public static class ExecutionResult {
        private final String output;
        private final boolean success;

        public ExecutionResult(String output, boolean success) {
            this.output = output;
            this.success = success;
        }

        public String getOutput() { return output; }
        public boolean isSuccess() { return success; }
    }
}

// Vulnerable configuration class
class JobConfig {
    private final Map<String, String> envVariables = new ConcurrentHashMap<>();
    private final Map<String, String> baseCommands = new ConcurrentHashMap<>();

    public JobConfig() {
        envVariables.put("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin");
        baseCommands.put("data_cleanup", "python /opt/scripts/cleanup.py");
        baseCommands.put("log_rotate", "logrotate --force /etc/logrotate.conf");
    }

    public Map<String, String> getEnvVariables() {
        return envVariables;
    }

    public String getBaseCommand(String taskId) {
        String command = baseCommands.get(taskId);
        if (command == null) {
            throw new IllegalArgumentException("Unknown task ID: " + taskId);
        }
        return command;
    }
}