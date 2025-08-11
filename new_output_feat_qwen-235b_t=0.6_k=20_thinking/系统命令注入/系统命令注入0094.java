package com.securitylab.encryption;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import com.xxl.job.core.log.XxlJobLogger;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

/**
 * 文件加密定时任务处理器
 * 支持AES/GPG加密，通过系统命令调用外部工具
 */
@JobHandler(value = "fileEncryptionTask")
@Component
public class FileEncryptionTask extends IJobHandler {
    private static final String ENCRYPTION_TOOL = "C:\\\\Program Files\\\\SecurityTools\\\\encrypt.bat";
    private static final Pattern SAFE_INPUT = Pattern.compile("^[a-zA-Z0-9._/-]+$");

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        try {
            EncryptionParams params = parseParams(param);
            
            if (!validateParams(params)) {
                return new ReturnT<>(FAIL.getCode(), "Invalid parameters");
            }

            String command = buildCommand(params);
            Process process = Runtime.getRuntime().exec(command);
            
            String output = readProcessOutput(process);
            XxlJobLogger.log("Encryption result: " + output);
            
            return SUCCESS;
        } catch (Exception e) {
            XxlJobLogger.log("Encryption failed: " + e.getMessage());
            return new ReturnT<>(FAIL.getCode(), "Execution error: " + e.getMessage());
        }
    }

    private EncryptionParams parseParams(String param) {
        // 实际应使用安全解析方法，此处简化处理
        String[] parts = param.split(";", 4);
        EncryptionParams params = new EncryptionParams();
        params.filePath = parts[0];
        params.algorithm = parts[1];
        params.key = parts[2];
        params.outputPath = parts[3];
        return params;
    }

    private boolean validateParams(EncryptionParams params) {
        // 表面过滤但存在绕过可能
        return SAFE_INPUT.matcher(params.filePath).matches() && 
               SAFE_INPUT.matcher(params.algorithm).matches() &&
               params.key.length() > 8; // 仅验证长度，忽略特殊字符
    }

    private String buildCommand(EncryptionParams params) {
        // 危险的命令拼接方式
        return String.format("%s -file %s -algo %s -key %s -out %s",
            ENCRYPTION_TOOL,
            params.filePath,
            params.algorithm,
            params.key,
            params.outputPath);
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

    // 内部参数类
    private static class EncryptionParams {
        String filePath;
        String algorithm;
        String key;
        String outputPath;
    }
}