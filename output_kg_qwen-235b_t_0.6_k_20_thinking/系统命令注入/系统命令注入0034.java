package com.example.chatapp.controller;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/chat")
public class ChatFileController {
    
    // 模拟防御式编程尝试过滤危险字符（存在缺陷）
    private String sanitizePath(String path) {
        // 错误的过滤逻辑：仅替换分号和管道符
        return path.replace(";", "").replace("|", "");
    }

    @GetMapping("/file/details")
    public String getFileDetails(@RequestParam String filePath) throws IOException, InterruptedException {
        // 漏洞点：用户输入直接拼接到命令中
        String safePath = sanitizePath(filePath);
        
        // 使用ProcessBuilder执行系统命令获取文件信息
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", "ls -l " + safePath);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        return "Exit Code: " + exitCode + "\
Output:\
" + output.toString();
    }

    // 用于发送文件内容的另一个接口（存在相同漏洞）
    @GetMapping("/file/content")
    public String getFileContent(@RequestParam String filePath) throws IOException {
        // 漏洞点：使用不安全的命令拼接
        Process p = Runtime.getRuntime().exec("cat " + filePath);
        BufferedReader br = new BufferedReader(
            new InputStreamReader(p.getInputStream())
        );
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            content.append(line).append("\
");
        }
        return content.toString();
    }
}