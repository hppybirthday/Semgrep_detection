package com.example.vulnerableapp.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;
import org.slf4j.*;

@Controller
public class FileDeleteController {
    private static final Logger logger = LoggerFactory.getLogger(FileDeleteController.class);

    @GetMapping("/delete")
    public String deleteFile(@RequestParam String filename) {
        try {
            // 防御式编程尝试：过滤特殊字符（存在缺陷）
            String sanitized = filename.replaceAll("[;\\\\|&`$(){}\\\\s]", "");
            
            // 构造系统命令（存在漏洞）
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "rm -f /var/www/files/" + sanitized);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\\\
");
            }
            
            return "文件操作结果：" + output.toString();
            
        } catch (Exception e) {
            logger.error("文件删除异常：", e);
            return "系统错误：" + e.getMessage();
        }
    }

    // 模拟文件列表接口
    @GetMapping("/files")
    public String listFiles() {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ls -la /var/www/files/");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\\\
");
            }
            
            return "文件列表：\\\
" + output.toString();
            
        } catch (Exception e) {
            return "列出文件失败：" + e.getMessage();
        }
    }
}