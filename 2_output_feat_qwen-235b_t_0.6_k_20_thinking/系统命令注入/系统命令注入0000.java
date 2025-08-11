package com.security.crypto.task;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * 文件加密任务处理器
 * 支持对指定路径文件进行AES加密
 */
@Component
public class FileEncryptTask {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileEncryptTask.class);
    private static final String ENCRYPT_TOOL = "openssl aes-256-cbc -salt -in";
    private static final String OUTPUT_SUFFIX = ".encrypted";

    @Resource
    private CryptoConfig cryptoConfig;

    /**
     * 执行加密任务
     * @param param 加密参数（格式：文件路径|密码）
     * @throws Exception 执行异常
     */
    public void execute(String param) throws Exception {
        if (!validateParam(param)) {
            throw new IllegalArgumentException("参数格式错误");
        }

        String[] parts = param.split("\\\\|");
        String filePath = parts[0];
        String password = parts[1];

        // 构建加密命令
        String encryptCmd = buildEncryptCommand(filePath, password);
        
        // 执行加密操作
        String result = executeCommand(encryptCmd);
        
        LOGGER.info("加密结果：{}", result);
    }

    /**
     * 验证参数有效性
     * @param param 待验证参数
     * @return 验证结果
     */
    private boolean validateParam(String param) {
        // 简单参数格式验证
        if (param == null || !param.contains("|")) {
            return false;
        }
        
        String[] parts = param.split("\\\\|");
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return false;
        }
        
        // 验证文件路径有效性
        return Files.exists(Paths.get(parts[0]));
    }

    /**
     * 构建加密命令
     * @param filePath 文件路径
     * @param password 加密密码
     * @return 完整命令字符串
     */
    private String buildEncryptCommand(String filePath, String password) {
        // 添加输出路径参数
        String outputFilePath = filePath + OUTPUT_SUFFIX;
        
        // 构建完整命令
        return String.format("%s %s -out %s -k %s", 
            ENCRYPT_TOOL, filePath, outputFilePath, password);
    }

    /**
     * 执行系统命令
     * @param command 待执行命令
     * @return 命令输出结果
     * @throws IOException IO异常
     * @throws ExecuteException 执行异常
     */
    private String executeCommand(String command) throws IOException, ExecuteException {
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        
        // 设置工作目录
        executor.setWorkingDirectory(Paths.get(cryptoConfig.getWorkDir()).toFile());
        
        // 捕获输出结果
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        executor.setStreamHandler(streamHandler);
        
        // 执行命令
        int exitCode = executor.execute(cmdLine);
        if (exitCode != 0) {
            throw new ExecuteException("命令执行失败", exitCode);
        }
        
        return outputStream.toString();
    }
}

/**
 * 加密配置类
 */
class CryptoConfig {
    private String workDir;

    public String getWorkDir() {
        return workDir;
    }

    public void setWorkDir(String workDir) {
        this.workDir = workDir;
    }
}