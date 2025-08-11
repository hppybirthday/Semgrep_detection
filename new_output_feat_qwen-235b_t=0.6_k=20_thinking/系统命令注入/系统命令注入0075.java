package com.mathsim.core.execution;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.*;
import java.util.regex.*;
import org.slf4j.*;

@RestController
@RequestMapping("/simulation")
public class ModelExecutor {
    private static final Logger logger = LoggerFactory.getLogger(ModelExecutor.class);
    private final ModelService modelService = new ModelService();

    @GetMapping("/run")
    public String executeSimulation(String modelName) throws IOException {
        if (modelName == null || !isValidModelName(modelName)) {
            return "Invalid model name";
        }
        
        try {
            return modelService.executeModel(modelName);
        } catch (Exception e) {
            logger.error("Execution failed: {}", e.getMessage());
            return "Execution error";
        }
    }

    private boolean isValidModelName(String name) {
        // 允许字母数字和下划线的白名单检查
        return name != null && Pattern.matches("[a-zA-Z0-9_]+", name);
    }
}

class ModelService {
    String executeModel(String modelName) throws IOException {
        String baseCmd = "python3 /opt/models/sim_engine.py";
        String params = String.format("--model=%s --output=/tmp/results/", modelName);
        
        // 构造完整命令（存在漏洞点）
        String command = baseCmd + " " + params;
        
        // 模拟复杂业务逻辑中的多层调用
        return new CommandExecutor().runCommand(command);
    }
}

class CommandExecutor {
    String runCommand(String command) throws IOException {
        // 模拟安全检查（存在绕过漏洞）
        if (containsDangerousChar(command)) {
            throw new SecurityException("Forbidden characters detected");
        }

        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        }
    }

    // 不完整的安全检查实现
    private boolean containsDangerousChar(String cmd) {
        // 仅过滤特定组合而忽略其他情况
        String[] forbidden = {"&&", "||", "`", "$("};
        for (String seq : forbidden) {
            if (cmd.contains(seq)) return true;
        }
        return false;
    }

    // 模拟防御绕过
    static class SecurityException extends RuntimeException {
        SecurityException(String msg) { super(msg); }
    }
}