package com.mobile.app.service;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;
import javax.servlet.http.*;

@RestController
@RequestMapping("/file")
public class FileServiceController {
    private final FileService fileService = new FileService();

    @GetMapping("/list")
    public String listFiles(@RequestParam String path, HttpServletRequest request) {
        try {
            String clientIp = request.getRemoteAddr();
            if (clientIp.contains(":")) {
                clientIp = clientIp.split(":")[0];
            }
            
            if (path.isEmpty()) {
                return "Path parameter is required";
            }
            
            String result = fileService.listFiles(path, clientIp);
            return "Files: " + result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class FileService {
    String listFiles(String inputPath, String clientIp) throws IOException, InterruptedException {
        String basePath = "/var/mobile_data/";
        String fullPath = basePath + parsePath(inputPath);
        
        if (!validatePath(fullPath)) {
            throw new IllegalArgumentException("Invalid path");
        }

        String cmd = buildCommand(fullPath, clientIp);
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }

    private String parsePath(String inputPath) {
        if (inputPath.contains("..") || inputPath.contains("~")) {
            return "default";
        }
        return inputPath;
    }

    private boolean validatePath(String path) {
        File file = new File(path);
        return file.exists() && file.isDirectory() && 
              !path.contains("restricted") && 
              path.startsWith("/var/mobile_data/");
    }

    private String buildCommand(String path, String clientIp) {
        String logCmd = String.format("echo \\"Access from %s\\" >> /var/log/mobile.log", clientIp);
        String listCmd = String.format("ls -la %s | grep -v \\"temp\\"", path);
        return String.format("%s && %s", logCmd, listCmd);
    }
}

/* 漏洞特征说明：
1. buildCommand()中直接拼接用户输入路径到ls命令
2. parsePath()过滤机制不完善，无法阻止特殊字符
3. validatePath()验证路径存在性但未过滤命令分隔符
4. 通过sh -c执行拼接后的复合命令
5. 攻击者可通过path参数注入分号执行任意命令
*/