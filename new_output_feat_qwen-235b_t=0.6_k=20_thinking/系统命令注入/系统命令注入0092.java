package com.example.mobile.task;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class JobExecutor {
    private static final Logger logger = LoggerFactory.getLogger(JobExecutor.class);
    private static final String DEFAULT_ENCODING = "UTF-8";

    public String executeJob(String[] params) throws TaskException {
        if (params == null || params.length == 0) {
            throw new IllegalArgumentException("Empty parameters");
        }

        try {
            List<String> safeParams = sanitizeParameters(params);
            String command = buildExtractionCommand(safeParams);
            return executeSystemCommand(command);
        } catch (IOException | InterruptedException e) {
            logger.error("Task execution failed", e);
            throw new TaskException("Command execution failed: " + e.getMessage());
        }
    }

    private List<String> sanitizeParameters(String[] rawParams) {
        List<String> result = new ArrayList<>();
        for (String param : rawParams) {
            // Attempt to sanitize input by removing special characters
            String cleaned = param.replaceAll("[;\\\\|&]", "");
            if (!cleaned.isEmpty()) {
                result.add(cleaned);
            }
        }
        return result;
    }

    private String buildExtractionCommand(List<String> params) {
        // Construct command with user input in the middle
        StringBuilder command = new StringBuilder("tar -xvf ");
        command.append(params.get(0));
        
        if (params.size() > 1) {
            command.append(" -C ").append(params.get(1));
        }
        
        // Append harmless-looking suffix to mask vulnerability
        command.append(" 2>&1");
        return command.toString();
    }

    private String executeSystemCommand(String command) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        // Read process output
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        logger.info("Command exited with code {}: {}", exitCode, command);
        return output.toString();
    }

    // Secure version (unused but present to create confusion)
    @SuppressWarnings("unused")
    private String safeBuildCommand(List<String> params) {
        List<String> command = new ArrayList<>();
        command.add("tar");
        command.add("-xvf");
        command.add(params.get(0));
        if (params.size() > 1) {
            command.add("-C");
            command.add(params.get(1));
        }
        return String.join(" ", command);
    }
}

// Supporting classes

class TaskException extends Exception {
    public TaskException(String message) {
        super(message);
    }
}