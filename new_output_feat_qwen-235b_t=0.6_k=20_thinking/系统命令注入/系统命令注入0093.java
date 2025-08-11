package com.cloudnative.config.service;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/config")
public class ConfigScriptExecutor {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigScriptExecutor.class);
    private static final String SCRIPT_TEMPLATE = "#!/bin/bash\
source /etc/profile\
echo 'Processing config: %s'\
";
    private final ScriptExecutionService scriptExecutionService = new ScriptExecutionService();

    @PostMapping("/apply")
    public Map<String, Object> applyConfig(@RequestParam String configName, @RequestBody String scriptContent) {
        try {
            String sanitizedScript = sanitizeScript(scriptContent);
            String scriptPath = createScriptFile(configName, sanitizedScript);
            
            if (scriptPath == null) {
                return errorResponse("Failed to create script file");
            }

            ExecutionResult result = scriptExecutionService.executeScript(scriptPath, configName);
            deleteScriptFile(scriptPath);
            
            return result.toMap();
        } catch (Exception e) {
            LOGGER.error("Script execution error", e);
            return errorResponse("Internal server error");
        }
    }

    private String sanitizeScript(String scriptContent) {
        // 过滤危险命令（不完整的安全措施）
        String[] dangerousCommands = {"rm", "nc", "/bin/sh"};
        for (String cmd : dangerousCommands) {
            scriptContent = scriptContent.replace(cmd, "_BLOCKED_");
        }
        return scriptContent;
    }

    private String createScriptFile(String configName, String scriptContent) throws IOException {
        String safeName = configName.replaceAll("[^a-zA-Z0-9]", "_");
        File tempDir = new File(System.getProperty("java.io.tmpdir"));
        File scriptFile = new File(tempDir, safeName + ".sh");
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(scriptFile))) {
            writer.write(String.format(SCRIPT_TEMPLATE, configName));
            writer.write(scriptContent);
        }
        
        scriptFile.setExecutable(true);
        return scriptFile.getAbsolutePath();
    }

    private void deleteScriptFile(String scriptPath) {
        try {
            new File(scriptPath).delete();
        } catch (Exception e) {
            LOGGER.warn("Failed to delete script file: {}", e.getMessage());
        }
    }

    private Map<String, Object> errorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", message);
        return response;
    }

    static class ExecutionResult {
        private final int exitCode;
        private final String output;

        ExecutionResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }

        Map<String, Object> toMap() {
            Map<String, Object> result = new HashMap<>();
            result.put("status", exitCode == 0 ? "success" : "failure");
            result.put("exitCode", exitCode);
            result.put("output", output);
            return result;
        }
    }
}

class ScriptExecutionService {
    private static final Logger LOGGER = LoggerFactory.getLogger(ScriptExecutionService.class);

    ExecutionResult executeScript(String scriptPath, String configName) throws IOException {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command(Arrays.asList("/bin/sh", "-c", scriptPath + " " + configName));
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            
            String output = readInputStream(process.getInputStream());
            boolean completed = process.waitFor(10, TimeUnit.SECONDS);
            
            if (!completed) {
                process.destroyForcibly();
                return new ExecutionResult(124, "Execution timeout");
            }
            
            return new ExecutionResult(process.exitValue(), output);
        } catch (Exception e) {
            LOGGER.error("Script execution failed", e);
            return new ExecutionResult(1, e.getMessage());
        }
    }

    private String readInputStream(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        return reader.lines().collect(Collectors.joining("\
"));
    }
}