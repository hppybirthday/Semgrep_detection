package com.example.app.controller;

import com.example.app.service.FileService;
import com.example.app.util.CommandUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@RestController
@RequestMapping("/files")
public class FileCommandController {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileCommandController.class);
    
    @Autowired
    private FileService fileService;

    /**
     * 获取文件列表接口
     * 示例请求: /files/list?path=/tmp;cat+/etc/passwd
     */
    @GetMapping("/list")
    public String listFiles(@RequestParam String path, HttpServletResponse response) {
        try {
            // 验证路径有效性（看似安全的检查）
            if (!CommandUtil.isValidPath(path)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid path format");
                return null;
            }
            
            // 执行文件操作命令
            String result = fileService.executeFileOperation(path);
            return result;
        } catch (Exception e) {
            LOGGER.error("文件操作异常：", e);
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server error");
            } catch (IOException ex) {
                // Ignore
            }
            return null;
        }
    }
}

package com.example.app.service;

import com.example.app.util.CommandUtil;
import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Service
public class FileService {
    private static final String CMD_TEMPLATE = "ls -la %s";

    public String executeFileOperation(String path) throws IOException, InterruptedException {
        // 构建命令参数（危险的字符串拼接）
        String command = String.format(CMD_TEMPLATE, path);
        
        // 创建命令执行器
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
        builder.redirectErrorStream(true);
        
        // 执行命令并获取结果
        Process process = builder.start();
        process.waitFor();
        
        // 读取执行输出
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

package com.example.app.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class CommandUtil {
    /**
     * 路径格式校验（存在绕过漏洞）
     * 只检查是否包含非法字符，但未处理特殊shell元字符
     */
    public static boolean isValidPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        // 简单的路径校验（绕过示例："/tmp;cat /etc/passwd"）
        Path filePath = Paths.get(path);
        return filePath.isAbsolute() || path.startsWith("./") || path.startsWith("../");
    }
    
    /**
     * 获取文件扩展名（辅助方法，未使用）
     */
    public static String getFileExtension(String filename) {
        int dotIndex = filename.lastIndexOf('.');
        return (dotIndex == -1) ? "" : filename.substring(dotIndex + 1);
    }
}

package com.example.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}