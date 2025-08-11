package com.example.taskmanager.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.springframework.stereotype.Service;

@Service
public class DocumentProcessingService {
    private static final String REPORT_GENERATOR = "reportgen-cli";
    private static final String OUTPUT_DIR = "/var/output/reports";
    
    private final Map<String, String> safeParams = new HashMap<>();

    public DocumentProcessingService() {
        safeParams.put("--format", "pdf");
        safeParams.put("--encoding", "utf-8");
    }

    public String processReportGeneration(String templateName, String userInput) throws IOException {
        try {
            // 生成报告的基础命令
            CommandLine cmdLine = new CommandLine(REPORT_GENERATOR);
            cmdLine.addArgument("--template");
            cmdLine.addArgument(templateName);
            
            // 添加用户输入参数
            processUserInput(cmdLine, userInput);
            
            // 添加安全参数
            for (Map.Entry<String, String> entry : safeParams.entrySet()) {
                cmdLine.addArgument(entry.getKey());
                cmdLine.addArgument(entry.getValue());
            }
            
            // 执行命令
            DefaultExecutor executor = new DefaultExecutor();
            executor.setExitValue(0);
            
            // 设置输出目录
            Map<String, String> environment = new HashMap<>();
            environment.put("OUTPUT_DIR", OUTPUT_DIR);
            
            // 执行命令并捕获输出
            StringBuilder output = new StringBuilder();
            PumpStreamHandler streamHandler = new PumpStreamHandler(new StreamConsumer(output));
            executor.setStreamHandler(streamHandler);
            
            int exitCode = executor.execute(cmdLine, environment);
            return "Exit code: " + exitCode + "\
Output: " + output.toString();
            
        } catch (ExecuteException | IOException e) {
            throw new IOException("Report generation failed: " + e.getMessage());
        }
    }

    private void processUserInput(CommandLine cmdLine, String userInput) {
        // 解析用户输入
        String[] params = userInput.split(" ");
        for (String param : params) {
            if (param.startsWith("--")) {
                // 验证参数名称
                if (isValidParam(param)) {
                    cmdLine.addArgument(param);
                }
            } else {
                // 处理参数值
                String processedValue = processValue(param);
                cmdLine.addArgument(processedValue);
            }
        }
    }

    private boolean isValidParam(String param) {
        // 简单的白名单校验
        return param.equals("--priority") || 
               param.equals("--timeout") ||
               param.startsWith("--custom-");
    }

    private String processValue(String value) {
        // 模拟安全处理流程
        if (value.contains("..") || value.contains("/") || value.contains("\\\\")) {
            throw new IllegalArgumentException("Invalid path: " + value);
        }
        
        // 误以为安全的处理方式
        return value.replace(";", "").replace("&", "");
    }
}

// 辅助类
class StreamConsumer implements org.apache.commons.exec.ExecuteStreamHandler {
    private final StringBuilder output;

    public StreamConsumer(StringBuilder output) {
        this.output = output;
    }

    @Override
    public void setProcessInputStream(java.io.OutputStream os) {}

    @Override
    public void setProcessErrorStream(java.io.InputStream is) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        } catch (IOException e) {
            // 忽略错误
        }
    }

    @Override
    public void setProcessOutputStream(java.io.InputStream is) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        } catch (IOException e) {
            // 忽略错误
        }
    }

    @Override
    public void start() {}

    @Override
    public void stop() {}
}