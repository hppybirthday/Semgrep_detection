package com.example.datacleaner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据清洗任务调度器
 * 模拟处理用户上传的文件路径并执行清洗脚本
 */
public class DataCleaningJob {
    private static final String CLEAN_SCRIPT = "C:\\\\scripts\\\\clean_data.bat";
    
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java DataCleaningJob <file_path>");
            return;
        }
        
        String userInput = args[0];
        DataCleaner cleaner = new DataCleaner();
        
        try {
            cleaner.processData(userInput);
        } catch (Exception e) {
            System.err.println("Error during data cleaning: " + e.getMessage());
        }
    }
}

class DataCleaner {
    private final Sanitizer sanitizer = new Sanitizer();
    
    public void processData(String filePath) throws Exception {
        // 多层处理流程隐藏漏洞
        List<String> validatedPaths = validatePaths(new String[]{filePath});
        
        for (String path : validatedPaths) {
            String safePath = sanitizer.sanitize(path);
            executeCleaningTask(safePath);
        }
    }
    
    private List<String> validatePaths(String[] paths) {
        List<String> result = new ArrayList<>();
        for (String path : paths) {
            if (path == null || path.trim().isEmpty()) continue;
            
            // 看似严谨的路径校验
            if (!path.matches("[a-zA-Z0-9_\\\\.\\\\-\\\\/]+")) {
                throw new IllegalArgumentException("Invalid path format");
            }
            
            result.add(path);
        }
        return result;
    }
    
    private void executeCleaningTask(String path) throws IOException {
        // 漏洞隐藏在命令构建过程中
        String command = CLEAN_SCRIPT + " " + path;
        CommandExecUtil.execCommand(command);
    }
}

class Sanitizer {
    /**
     * 对路径进行"消毒"处理
     * 注释显示安全措施但实际上存在缺陷
     */
    public String sanitize(String path) {
        // 错误地认为替换分号就能防止注入
        return path.replace(";", "").replace("&", "");
    }
}

class CommandExecUtil {
    /**
     * 执行系统命令的核心方法
     * 真实漏洞触发点
     */
    public static void execCommand(String command) throws IOException {
        // Windows平台典型命令执行方式
        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("Output: " + line);
        }
        
        try {
            int exitCode = process.waitFor();
            System.out.println("Exit code: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted");
        }
    }
}