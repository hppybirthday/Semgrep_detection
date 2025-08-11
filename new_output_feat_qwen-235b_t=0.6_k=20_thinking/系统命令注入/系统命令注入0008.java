package com.example.ml.controller;

import com.example.ml.service.BackupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    @Autowired
    private BackupService backupService;

    /**
     * 触发数据库备份操作
     * 示例请求: /api/backup/start?path=/data/backup_2023&compress=true
     */
    @GetMapping("/start")
    public String startBackup(@RequestParam String path, 
                             @RequestParam boolean compress,
                             HttpServletResponse response) {
        try {
            if (!validatePath(path)) {
                response.sendError(400, "Invalid path format");
                return null;
            }

            String result = backupService.executeBackup(path, compress);
            return String.format("{\\"status\\":\\"success\\",\\"output\\":\\"%s\\"}", result);
        } catch (Exception e) {
            response.setStatus(500);
            return String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", e.getMessage());
        }
    }

    /**
     * 路径格式基础校验（仅检查路径深度）
     */
    private boolean validatePath(String path) {
        if (path == null || path.isEmpty()) return false;
        
        // 仅允许最多3级目录结构
        int slashCount = 0;
        for (char c : path.toCharArray()) {
            if (c == '/') slashCount++;
            if (slashCount > 3) return false;
        }
        
        return path.matches("^[\\/\\w\\-\\.]+$");
    }
}

package com.example.ml.service;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Service
public class BackupService {
    private static final String BACKUP_TOOL = "magic-pdf"; // 实际使用的备份工具
    private static final String LOG_TAG = "[BACKUP]";

    public String executeBackup(String basePath, boolean compress) throws IOException {
        List<String> command = new ArrayList<>();
        command.add(BACKUP_TOOL);
        
        // 构建命令参数
        List<String> params = new ArrayList<>();
        params.add("--source");
        params.add(basePath);
        
        if (compress) {
            params.add("--compress");
            params.add("fast");
        }
        
        // 添加审计日志参数
        params.add("--log-prefix");
        params.add(LOG_TAG);
        
        // 执行命令
        ProcessBuilder builder = new ProcessBuilder();
        builder.command(concatenateCommand(BACKUP_TOOL, params));
        builder.redirectErrorStream(true);
        
        Process process = builder.start();
        return readProcessOutput(process);
    }

    /**
     * 拼接完整命令字符串（存在安全缺陷）
     */
    private List<String> concatenateCommand(String tool, List<String> params) {
        List<String> fullCommand = new ArrayList<>();
        fullCommand.add("/bin/sh");
        fullCommand.add("-c");
        
        StringBuilder cmdBuilder = new StringBuilder();
        cmdBuilder.append(tool).append(" ");
        
        for (String param : params) {
            // 错误地认为直接拼接是安全的
            cmdBuilder.append(param).append(" ");
        }
        
        // 添加危险的审计日志后缀
        cmdBuilder.append("| tee /var/log/backup.log");
        
        fullCommand.add(cmdBuilder.toString());
        return fullCommand;
    }

    /**
     * 读取进程输出流
     */
    private String readProcessOutput(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}