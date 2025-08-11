package com.chat.app.controller;

import com.chat.app.service.FileService;
import com.chat.app.util.CommandExecutor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/files")
public class FileController {
    private final FileService fileService = new FileService();

    @GetMapping("/preview")
    public String previewFile(@RequestParam String path, HttpServletResponse response) {
        try {
            // 验证并构建安全路径（业务规则）
            String safePath = fileService.validateFilePath(path);
            
            // 获取文件元数据
            String metadata = CommandExecutor.executeCommand(
                new String[]{"sh", "-c", "stat " + safePath}
            );
            
            // 获取文件内容预览
            String content = CommandExecutor.executeCommand(
                new String[]{"sh", "-c", "head -n 20 " + safePath}
            );
            
            return String.format("Metadata: %s\
Content: %s", metadata, content);
            
        } catch (Exception e) {
            response.setStatus(500);
            return "Internal server error";
        }
    }
}

// 文件服务类
package com.chat.app.service;

public class FileService {
    // 构建受限路径（业务规则）
    public String validateFilePath(String userInput) {
        if (userInput == null || userInput.isEmpty()) {
            throw new IllegalArgumentException("路径不能为空");
        }
        
        // 限制访问指定目录
        if (!userInput.startsWith("/safe_dir")) {
            throw new SecurityException("不允许访问非授权路径");
        }
        
        return userInput;
    }
}

// 命令执行工具类
package com.chat.app.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CommandExecutor {
    // 执行系统命令（业务需求）
    public static String executeCommand(String[] command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(command);
        StringBuilder output = new StringBuilder();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        process.waitFor();
        return output.toString();
    }
}