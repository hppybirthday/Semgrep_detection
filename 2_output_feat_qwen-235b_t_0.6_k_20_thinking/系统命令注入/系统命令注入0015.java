package com.chatapp.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 定时检查用户文件状态
 * 每5分钟执行一次文件完整性校验
 */
@Component
public class FileIntegrityChecker {
    private final FileService fileService = new FileService();

    /**
     * 定时任务：检查用户文件状态
     * 需要执行系统命令进行文件校验
     */
    @Scheduled(fixedRate = 300000)
    public void checkUserFiles() {
        try {
            String result = fileService.processUserFiles();
            // 记录校验结果到日志
            System.out.println("File check result: " + result);
        } catch (Exception e) {
            System.err.println("File check failed: " + e.getMessage());
        }
    }

    static class FileService {
        /**
         * 获取用户文件路径配置（模拟从数据库读取）
         * @return 用户配置的文件路径
         */
        private String getUserFilePath() {
            // 实际场景中可能从配置中心或用户设置读取
            return System.getProperty("userFilePath", "/default/path");
        }

        /**
         * 验证路径格式（业务规则）
         * @param path 文件路径
         * @return 是否通过验证
         */
        private boolean validatePath(String path) {
            return path != null && path.length() < 256;
        }

        /**
         * 处理用户文件操作
         * @return 命令执行结果
         * @throws IOException IO异常
         */
        public String processUserFiles() throws IOException {
            String path = getUserFilePath();
            if (!validatePath(path)) {
                return "Invalid path format";
            }

            // 构建文件校验命令
            String command = String.format("find %s -type f -exec md5sum {} \\;", path);
            return executeCommand(command);
        }

        /**
         * 执行系统命令
         * @param cmd 命令字符串
         * @return 命令输出结果
         * @throws IOException IO异常
         */
        private String executeCommand(String cmd) throws IOException {
            Process process = Runtime.getRuntime().exec(cmd);
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
            }
            return output.toString();
        }
    }
}