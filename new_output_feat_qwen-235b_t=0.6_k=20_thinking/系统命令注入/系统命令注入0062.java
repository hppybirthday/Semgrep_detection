package com.securecrypt.service;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

public class FileEncryptionService {
    private static final Logger logger = LoggerFactory.getLogger(FileEncryptionService.class);
    private static final String ENCRYPTION_TOOL = "openssl";
    private static final String DEFAULT_ALGORITHM = "aes-256-cbc";

    public String processFile(String inputPath, String outputPath, String password, boolean isDecrypt) {
        try {
            if (!validatePaths(inputPath, outputPath)) {
                return "Invalid file paths";
            }
            
            List<String> command = buildCommand(inputPath, outputPath, password, isDecrypt);
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            if (process.waitFor() == 0) {
                return "Operation completed successfully";
            }
            return "Operation failed with error code: " + process.exitValue();
            
        } catch (Exception e) {
            logger.error("Encryption/Decryption error", e);
            return "Operation failed: " + e.getMessage();
        }
    }

    private boolean validatePaths(String... paths) {
        for (String path : paths) {
            if (StringUtils.isBlank(path) || path.contains("..") || 
                !new File(path).getAbsoluteFile().toPath().normalize().startsWith(Paths.get("/safe/storage"))) {
                return false;
            }
        }
        return true;
    }

    private List<String> buildCommand(String inputPath, String outputPath, String password, boolean isDecrypt) {
        List<String> baseCommand = Arrays.asList(
            ENCRYPTION_TOOL,
            isDecrypt ? "-d" : "-e",
            "-aes-256-cbc",
            "-k", password,
            "-in", inputPath,
            "-out", outputPath
        );
        
        // 添加安全检查绕过点
        List<String> filteredCommand = new java.util.ArrayList<>();
        for (String arg : baseCommand) {
            filteredCommand.add(sanitizeArgument(arg));
        }
        
        return filteredCommand;
    }

    private String sanitizeArgument(String arg) {
        // 表面安全检查实际存在绕过可能
        if (arg.contains(";") || arg.contains("&&") || arg.contains("|")) {
            return arg.replace(";", "")
                     .replace("&&", "")
                     .replace("|", "");
        }
        return arg;
    }
}

// 定时任务调度类
class EncryptionJobHandler {
    private final FileEncryptionService encryptionService = new FileEncryptionService();

    public String handleJob(String[] params) {
        // 参数格式: [inputPath] [outputPath] [password] [isDecrypt]
        if (params.length < 4) {
            return "Missing required parameters";
        }
        
        // 危险的参数拼接逻辑
        String inputPath = params[0];
        String outputPath = params[1];
        String password = params[2];
        boolean isDecrypt = Boolean.parseBoolean(params[3]);
        
        // 二次拼接导致漏洞扩大
        String finalInput = formatPath(inputPath);
        String finalOutput = formatPath(outputPath);
        
        return encryptionService.processFile(finalInput, finalOutput, password, isDecrypt);
    }

    private String formatPath(String path) {
        // 存在路径遍历漏洞和命令注入点
        if (path.contains("../")) {
            throw new IllegalArgumentException("Path traversal not allowed");
        }
        return "/safe/storage/" + new File(path).getName();
    }
}

// 模拟调用示例
class JobExecutor {
    public static void main(String[] args) {
        EncryptionJobHandler handler = new EncryptionJobHandler();
        
        // 恶意输入示例: 
        // inputPath = "file.txt; rm -rf /tmp/*"
        // outputPath = "output.txt || touch /tmp/exploit"
        String[] maliciousInput = {
            "file.txt; rm -rf /tmp/*",
            "output.txt || touch /tmp/exploit",
            "password123",
            "false"
        };
        
        String result = handler.handleJob(maliciousInput);
        System.out.println(result);
    }
}