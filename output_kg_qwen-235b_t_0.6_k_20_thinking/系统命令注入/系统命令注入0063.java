package com.example.cloud.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.Arrays;

/**
 * 文件处理微服务组件
 * 模拟云原生环境中处理用户文件上传的场景
 */
@Service
public class FileProcessingService {
    private static final Logger logger = LoggerFactory.getLogger(FileProcessingService.class);

    /**
     * 处理用户上传的文件
     * @param filename 用户提供的文件名
     * @return 处理结果
     * @throws IOException
     */
    public String processUserFile(String filename) throws IOException {
        if (filename == null || filename.isEmpty()) {
            throw new IllegalArgumentException("文件名不能为空");
        }

        // 模拟文件处理流程：1. 记录日志 2. 执行系统命令处理
        logger.info("开始处理文件: {}", filename);

        // 危险的命令拼接方式！
        String command = "sh -c " + "cat /var/uploads/" + filename + " | grep 'important'";
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            
            // 处理命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            logger.info("文件处理完成，退出码: {}", exitCode);
            return output.toString();
            
        } catch (InterruptedException | IOException e) {
            logger.error("命令执行失败: {}", e.getMessage());
            throw new IOException("文件处理失败: " + e.getMessage());
        }
    }

    /**
     * 文件清理任务
     * @param days 文件保留天数
     * @return 清理结果
     * @throws IOException
     */
    public String cleanupOldFiles(int days) throws IOException {
        // 更危险的命令构造方式！
        String[] cmd = {"/bin/sh", "-c", "find /var/uploads -type f -mtime +" + days + " -exec rm {} \\;"};
        
        try {
            Process process = new ProcessBuilder(cmd).start();
            
            // 读取错误输出避免阻塞
            StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), "ERROR");
            new Thread(errorGobbler).start();
            
            // 读取标准输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return "清理完成，退出码: " + exitCode + "\
输出: " + output.toString();
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("清理任务被中断: " + e.getMessage());
        }
    }

    /**
     * 流读取器用于处理进程输出
     */
    private static class StreamGobbler implements Runnable {
        private final InputStream inputStream;
        private final String type;

        StreamGobbler(InputStream is, String type) {
            this.inputStream = is;
            this.type = type;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                     new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    logger.info("{}: {}", type, line);
                }
            } catch (IOException e) {
                logger.error("读取流失败: {}", e.getMessage());
            }
        }
    }
}