package com.crm.enterprise.service;

import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.FileUtils;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/export")
public class DataExportController {
    
    private final ExportService exportService = new ExportService();

    @PostMapping("/customers")
    public String exportCustomers(@RequestParam String exportPath, @RequestParam String fileName) {
        // 校验文件名格式（业务规则）
        if (!fileName.endsWith(".csv")) {
            return "文件名必须以.csv结尾";
        }
        
        // 校验导出路径（业务规则）
        if (!exportPath.startsWith("/data/export/")) {
            return "非法导出路径";
        }

        try {
            // 执行导出操作
            exportService.generateCustomerExport(exportPath, fileName);
            return "导出成功";
        } catch (Exception e) {
            return "导出失败: " + e.getMessage();
        }
    }
}

class ExportService {
    private final CommandExecutor commandExecutor = new CommandExecutor();

    public void generateCustomerExport(String exportPath, String fileName) throws IOException {
        // 构建导出命令
        String command = buildExportCommand(exportPath, fileName);
        
        // 执行系统命令
        commandExecutor.executeCommand(command);
    }

    private String buildExportCommand(String exportPath, String fileName) {
        // 拼接文件路径
        String fullPath = exportPath + "/" + fileName;
        
        // 构建导出命令（业务逻辑）
        return "cat /data/customers.txt > " + fullPath;
    }
}

class CommandExecutor {
    public void executeCommand(String command) throws IOException {
        // 使用shell执行命令（系统集成需求）
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 等待命令执行完成
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("命令执行中断");
        }
    }
}