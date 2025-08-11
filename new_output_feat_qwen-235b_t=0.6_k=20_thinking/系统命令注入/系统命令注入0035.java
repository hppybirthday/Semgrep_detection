package com.taskmanager.core;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.servlet.http.*;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    private final TaskService taskService = new TaskService();

    @PostMapping("/execute")
    public String executeTask(@RequestParam String cmd, HttpServletRequest request) {
        String clientIp = getClientIP(request);
        if (!isValidCommand(cmd)) {
            return "Invalid command format";
        }
        
        try {
            return taskService.runSystemCommand(cmd, clientIp);
        } catch (Exception e) {
            return "Execution failed: " + e.getMessage();
        }
    }

    private boolean isValidCommand(String cmd) {
        // 仅允许字母数字和基本文件路径字符
        return Pattern.matches("[a-zA-Z0-9\\\\/\\\\.\\\\-]+", cmd);
    }

    private String getClientIP(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}

class TaskService {
    private static final String LOG_DIR = "/var/log/tasks/";
    
    public String runSystemCommand(String cmd, String clientIp) throws Exception {
        String safeCmd = sanitizeCommand(cmd);
        String logFile = generateLogFile(clientIp);
        
        // 构造带日志记录的命令链
        String finalCommand = String.format("(%s) && (echo \\"$(date) CMD: %s\\" >> %s)", 
            safeCmd, cmd, logFile);
            
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", finalCommand});
        return readProcessOutput(process);
    }

    private String sanitizeCommand(String cmd) {
        // 尝试过滤危险字符（存在绕过漏洞）
        return cmd.replaceAll("([&|;`\\\\s]+)", " $1 ").replaceAll("\\s+", " ");
    }

    private String generateLogFile(String clientIp) {
        // 将IP地址转换为日志文件名
        return LOG_DIR + clientIp.replaceAll("[^a-zA-Z0-9]", "_") + "_audit.log";
    }

    private String readProcessOutput(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}