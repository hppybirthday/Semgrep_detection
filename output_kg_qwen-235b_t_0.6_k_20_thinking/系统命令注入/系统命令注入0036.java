package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;

@Controller
@RequestMapping("/files")
public class FileViewerController {
    
    // 模拟文件服务器日志记录功能
    private void logUserRequest(String filename, String remoteAddr) {
        System.out.println("User[" + remoteAddr + "] requested file: " + filename);
    }

    // 模拟权限验证（实际未正确实现）
    private boolean checkPermission(String filename, String token) {
        return filename != null && filename.startsWith("/safe_dir/");
    }

    // 模拟文件预览功能
    @GetMapping("/preview")
    @ResponseBody
    public String previewFile(
            @RequestParam("filename") String filename,
            @RequestParam("token") String token,
            @RequestHeader("X-Forwarded-For") String remoteAddr) {

        // 记录用户请求
        logUserRequest(filename, remoteAddr);

        // 权限验证（存在逻辑缺陷）
        if (!checkPermission(filename, token)) {
            return "Access Denied";
        }

        // 构造系统命令（存在严重漏洞）
        String command = "cat " + filename;
        
        // 执行命令并获取结果
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    // 模拟文件列表功能（存在相同漏洞）
    @GetMapping("/list")
    @ResponseBody
    public String listFiles(@RequestParam("dir") String dir) {
        try {
            Process process = Runtime.getRuntime().exec("ls -la " + dir);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error listing directory: " + e.getMessage();
        }
    }
}