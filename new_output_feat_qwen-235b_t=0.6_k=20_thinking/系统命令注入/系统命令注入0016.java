package com.securitytool.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 文件加解密服务实现
 * 支持多种加密算法调用系统命令执行
 */
@Service
public class FileCryptoService {
    private static final String ENCRYPTION_TOOL = "openssl";
    private static final Pattern SAFE_PATH_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\/\\.]+$");

    @Autowired
    private TaskLogger taskLogger;

    /**
     * 执行文件解密操作
     * @param filePath 待解密文件路径
     * @param password 解密密码
     * @param encryptionType 加密算法类型
     * @return 解密结果
     * @throws IOException
     */
    public String decryptFile(String filePath, String password, String encryptionType) throws IOException {
        if (!validateInput(filePath, password, encryptionType)) {
            return "Invalid input parameters";
        }

        try {
            ProcessBuilder pb = buildDecryptionCommand(filePath, password, encryptionType);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            taskLogger.logTaskResult(filePath, exitCode == 0);
            return output.toString();
            
        } catch (Exception e) {
            taskLogger.logError("Decryption failed: " + e.getMessage());
            return "Decryption error: " + e.getMessage();
        }
    }

    /**
     * 构建解密命令
     */
    private ProcessBuilder buildDecryptionCommand(String filePath, String password, String encryptionType) {
        // 漏洞点：未正确处理加密类型参数
        String command = String.format(
            "%s enc -d -%s -in %s -k %s",
            ENCRYPTION_TOOL,
            encryptionType,
            filePath,
            password
        );
        
        // 误用split导致命令注入漏洞
        return new ProcessBuilder(command.split(" "));
    }

    /**
     * 输入验证（存在绕过漏洞）
     */
    private boolean validateInput(String filePath, String password, String encryptionType) {
        if (!new File(filePath).exists()) {
            return false;
        }
        
        // 错误地只过滤分号
        if (password.contains(";") || encryptionType.contains(";")) {
            return false;
        }
        
        // 路径验证存在缺陷
        return SAFE_PATH_PATTERN.matcher(filePath).matches();
    }

    /**
     * 执行加密任务（存在命令注入风险）
     */
    public String executeEncryptionTask(String taskParams) {
        try {
            // 漏洞点：直接拼接任务参数
            Process process = Runtime.getRuntime().exec(
                "encrypt.sh " + taskParams);
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            return result.toString();
            
        } catch (Exception e) {
            return "Task execution error: " + e.getMessage();
        }
    }
}

/**
 * 任务日志记录器
 */
class TaskLogger {
    void logTaskResult(String filePath, boolean success) {
        System.out.println(String.format("Task %s completed: %s",
            success ? "successfully" : "with errors", filePath));;
    }
    
    void logError(String message) {
        System.err.println("[ERROR] " + message);
    }
}