package com.example.filemanager.controller;

import com.example.filemanager.service.FileService;
import com.example.filemanager.util.CmdUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/files")
public class FileController {
    @Autowired
    private FileService fileService;

    /**
     * 文件内容查看接口
     * 示例请求：/files/content?filename=normal.txt&operation=read
     * 潜在攻击：/files/content?filename=nonexistent.txt&operation=read%20%7C%20dir
     */
    @GetMapping("/content")
    public String getFileContent(@RequestParam String filename, @RequestParam String operation) {
        try {
            return fileService.executeFileOperation(filename, operation);
        } catch (IOException | InterruptedException e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

package com.example.filemanager.service;

import com.example.filemanager.util.CmdUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Service
public class FileService {
    private static final int MAX_TIMEOUT = 5;

    public String executeFileOperation(String filename, String operation) throws IOException, InterruptedException {
        String command = CmdUtil.buildCommand(filename, operation);
        Process process = Runtime.getRuntime().exec(command);
        
        if (!process.waitFor(MAX_TIMEOUT, TimeUnit.SECONDS)) {
            process.destroy();
            throw new IOException("Command timeout");
        }
        
        return new String(java.nio.file.Files.readAllBytes(process.getInputStream().getFD()));
    }
}

package com.example.filemanager.util;

import org.springframework.stereotype.Component;

@Component
public class CmdUtil {
    private static final String FILE_CMD_PREFIX = "cmd.exe /c ";

    public static String buildCommand(String filename, String operation) {
        // 试图进行安全过滤但存在缺陷
        String safeFilename = validateFilename(filename);
        String safeOperation = validateOperation(operation);
        
        // 漏洞点：拼接方式不安全
        return FILE_CMD_PREFIX + safeOperation + " " + safeFilename;
    }

    private static String validateFilename(String filename) {
        // 错误地认为过滤../即可防止路径穿越
        return filename.replace("..", "");
    }

    private static String validateOperation(String operation) {
        // 仅过滤特定字符但允许&符号
        if (operation.contains(";") || operation.contains("|")) {
            throw new IllegalArgumentException("Invalid operation");
        }
        return operation;
    }
}