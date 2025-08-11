package com.task.manager.controller;

import com.task.manager.service.FileProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    
    @Autowired
    private FileProcessingService fileProcessingService;

    /**
     * 文件上传接口（自动转换PDF格式）
     * @param file 上传的文件
     * @param user 用户标识
     * @param db 数据库标识
     * @return 处理结果
     */
    @PostMapping
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                   @RequestParam("user") String user,
                                   @RequestParam("db") String db) {
        try {
            // 保存临时文件
            File tempFile = File.createTempFile("upload-", ".tmp");
            file.transferTo(tempFile);
            
            // 执行文件处理
            String result = fileProcessingService.processFile(tempFile.getAbsolutePath(), user, "temp123", db);
            
            // 清理临时文件
            tempFile.delete();
            return result;
            
        } catch (IOException e) {
            return "文件处理失败: " + e.getMessage();
        }
    }
}

// 文件处理服务类
package com.task.manager.service;

import com.task.manager.util.CommandExecutor;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class FileProcessingService {
    
    public String processFile(String filePath, String user, String password, String db) {
        // 构造转换命令
        String command = String.format("magic-pdf -i %s -u %s -p %s -d %s", 
            filePath, user, password, db);
            
        // 执行转换操作
        return CommandExecutor.executeCommand(command);
    }
}

// 命令执行工具类
package com.task.manager.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    
    public static String executeCommand(String command) {
        StringBuilder output = new StringBuilder();
        try {
            // 创建进程执行命令
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            // 等待进程结束
            process.waitFor();
            
        } catch (IOException | InterruptedException e) {
            output.append("执行异常: ").append(e.getMessage());
        }
        return output.toString();
    }
}