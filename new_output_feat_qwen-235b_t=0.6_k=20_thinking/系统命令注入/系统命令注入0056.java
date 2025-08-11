package com.example.datacleaner;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/clean")
public class DataCleanerController {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataCleanerController.class);
    private final LogAnalyzerService logAnalyzer = new LogAnalyzerService();

    @GetMapping("/logs")
    public String analyzeLogs(@RequestParam String logPath, HttpServletResponse response) {
        try {
            if (!isValidPath(logPath)) {
                response.setStatus(400);
                return "Invalid log path";
            }

            String result = logAnalyzer.processLogFile(logPath);
            return "Analysis result: " + result;
        } catch (Exception e) {
            LOGGER.error("Error processing log file: {}", logPath, e);
            response.setStatus(500);
            return "Internal server error";
        }
    }

    private boolean isValidPath(String path) {
        // 简单的路径校验（绕过方式：使用../或编码）
        return path.startsWith("/var/log/") && !path.contains("..");
    }
}

class LogAnalyzerService {
    private final CommandLineExecutor executor = new CommandLineExecutor();

    public String processLogFile(String logPath) throws IOException {
        // 构造日志分析命令
        List<String> command = new ArrayList<>();
        command.add("sh");
        command.add("-c");
        command.add("grep -E 'ERROR|WARN' " + sanitizeInput(logPath) + " | wc -l");
        
        // 执行命令并返回结果
        return executor.executeCommand(command);
    }

    // 漏洞：不完整的输入过滤
    private String sanitizeInput(String input) {
        // 表面过滤但存在绕过可能
        return input.replace(";", "").replace("&", "").replace("|", "");
    }
}

class CommandLineExecutor {
    public String executeCommand(List<String> command) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        // 读取命令输出
        String result = FileUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8)
                              .toString();
        
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("Command execution failed with exit code " + exitCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }
        
        return result;
    }
}