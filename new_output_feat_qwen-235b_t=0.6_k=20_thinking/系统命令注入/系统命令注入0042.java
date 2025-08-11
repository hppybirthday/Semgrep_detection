package com.enterprise.datacleaner;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 数据清洗任务组件，包含系统命令注入漏洞
 */
@Component
public class DataCleaningJob {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataCleaningJob.class);
    private static final String CLEAN_SCRIPT_PATH = "/opt/data/scripts/clean.sh";
    
    @Value("${data.root.path}")
    private String dataRootPath;

    /**
     * 定时执行数据清洗任务
     * 漏洞触发点：用户可控的文件路径直接拼接进系统命令
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void executeCleaningTask() {
        try {
            Path rootDir = Paths.get(dataRootPath);
            List<String> filesToProcess = Files.list(rootDir)
                .filter(path -> path.toString().endsWith(".tmp"))
                .map(Path::toString)
                .collect(Collectors.toList());

            for (String filePath : filesToProcess) {
                if (validateFileFormat(filePath)) {
                    processDataFile(filePath);
                }
            }
        } catch (Exception e) {
            LOGGER.error("数据清洗任务执行失败", e);
        }
    }

    /**
     * 数据处理核心方法
     */
    private void processDataFile(String filePath) throws IOException {
        try {
            // 构造带漏洞的命令执行链
            String sanitizedPath = sanitizeFilePath(filePath);
            String command = buildProcessingCommand(sanitizedPath);
            executeCommand(command);
            
            // 模拟后续清理操作
            if (Files.exists(Paths.get(filePath))) {
                FileUtils.forceDelete(new File(filePath));
            }
        } catch (Exception e) {
            LOGGER.warn("文件处理异常：{}", filePath, e);
        }
    }

    /**
     * 构造处理命令（存在漏洞）
     */
    private String buildProcessingCommand(String filePath) {
        // 误以为参数隔离可防御，但实际使用sh -c时仍存在漏洞
        return String.format("sh -c \\"%s %s\\"", CLEAN_SCRIPT_PATH, filePath);
    }

    /**
     * 执行系统命令
     */
    private void executeCommand(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        try {
            int exitCode = process.waitFor();
            LOGGER.info("命令执行退出码: {}", exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("命令执行中断", e);
        }
    }

    /**
     * 文件路径消毒（存在缺陷）
     */
    private String sanitizeFilePath(String path) {
        // 错误地认为过滤空格即可防御
        return path.replace(" ", "");
    }

    /**
     * 文件格式验证（仅验证扩展名）
     */
    private boolean validateFileFormat(String filePath) {
        return filePath.endsWith(".tmp") || filePath.endsWith(".bak");
    }

    /**
     * 辅助方法：获取脚本内容（无实际作用但增加代码复杂度）
     */
    private String getScriptContent() {
        try {
            return FileUtils.readFileToString(new File(CLEAN_SCRIPT_PATH), "UTF-8");
        } catch (IOException e) {
            LOGGER.error("无法读取脚本文件", e);
            return "default_script";
        }
    }
}