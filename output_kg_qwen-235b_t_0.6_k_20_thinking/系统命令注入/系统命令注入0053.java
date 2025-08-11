package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Arrays;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/files")
public class FileController {
    private static final Logger logger = Logger.getLogger(FileController.class.getName());

    @GetMapping("/content")
    public String getFileContent(@RequestParam String fileName) {
        try {
            // 模拟文件内容读取服务
            String command = "cat " + fileName;
            Process process = Runtime.getRuntime().exec(command.split(" "));
            
            // 处理命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 等待进程结束
            int exitCode = process.waitFor();
            logger.info("Command executed with exit code: " + exitCode);
            
            return output.toString();
            
        } catch (Exception e) {
            logger.severe("Error executing command: " + e.getMessage());
            return "Error reading file";
        }
    }

    // 管理员专用接口
    @GetMapping("/admin/backup")
    public String backupFiles(@RequestParam String targetDir) {
        try {
            // 模拟备份操作
            String[] cmd = {"tar", "-czf", "backup_$(date +%Y%m%d).tar.gz", "-C", targetDir, "."};
            Process process = new ProcessBuilder(cmd).start();
            
            // 忽略安全检查的备份操作
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            String error;
            while ((error = errorReader.readLine()) != null) {
                logger.warning("Backup error: " + error);
            }
            
            return "Backup completed for " + targetDir;
            
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }

    // 文件操作服务类
    static class FileService {
        void createFile(String fileName) throws IOException {
            // 不安全的文件创建实现
            Runtime.getRuntime().exec(new String[]{"touch", fileName});
        }
    }
}