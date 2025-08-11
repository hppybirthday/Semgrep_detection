package com.example.chatapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/files")
public class FileController {
    private static final String BASE_DIR = "/var/chatapp/uploads/";

    // 函数式接口示例
    private Function<String, String> sanitizePath = path -> {
        // 错误的过滤逻辑：只替换../但未处理其他情况
        return path.replaceAll("\\.\\./", "");
    };

    @GetMapping("/download")
    public String downloadFile(@RequestParam String filename) {
        try {
            // 漏洞点：直接拼接用户输入的文件名
            String unsafePath = BASE_DIR + filename;
            
            // 错误的路径清理实现（示例）
            String safePath = sanitizePath.apply(unsafePath);
            
            // 更危险的实现方式（真实漏洞点）
            File file = new File(BASE_DIR + filename);
            
            if (!file.exists()) {
                return "File not found";
            }

            // 读取文件内容（危险操作）
            return Files.lines(file.toPath())
                        .collect(Collectors.joining("\
"));
                        
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 文件上传处理示例（扩展攻击面）
    @PostMapping("/upload")
    public String uploadFile(@RequestParam String content, 
                           @RequestParam String filename) {
        try {
            // 漏洞点2：未校验文件名合法性
            File file = new File(BASE_DIR + filename);
            
            // 潜在的webshell上传风险
            if (filename.toLowerCase().endsWith(".jsp") || 
                filename.toLowerCase().endsWith(".php")) {
                return "File type not allowed";
            }

            Files.write(file.toPath(), content.getBytes());
            return "Upload successful";
            
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    // 路径遍历漏洞利用示例（演示攻击路径）
    @GetMapping("/view")
    public String viewFile(@RequestParam String path) {
        try {
            // 危险的路径拼接方式
            File file = new File("/opt/chatapp/data/" + path);
            
            // 更隐蔽的漏洞：使用normalize()但未正确验证
            Path normalized = Paths.get(file.getAbsolutePath()).normalize();
            
            // 如果路径未正确限制，攻击者可通过多种方式绕过
            if (!normalized.toString().startsWith("/opt/chatapp/data/")) {
                return "Access denied";
            }

            return new String(Files.readAllBytes(normalized));
            
        } catch (Exception e) {
            return "View error: " + e.getMessage();
        }
    }
}