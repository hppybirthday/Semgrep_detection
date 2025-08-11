package com.example.vulnerablecrawler;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Arrays;

@RestController
@RequestMapping("/crawl")
public class VulnerableCrawler {
    
    @GetMapping
    public String crawlPage(@RequestParam String url) {
        try {
            // 模拟爬虫下载页面内容
            ProcessBuilder pb = new ProcessBuilder("curl", url);
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
            return "Crawled content (exit code " + exitCode + "):\
" + output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟爬取本地文件的危险功能
    @GetMapping("/file")
    public String crawlFile(@RequestParam String filename) {
        try {
            // 危险的命令拼接方式
            ProcessBuilder pb = new ProcessBuilder("cat", filename);
            Process process = pb.start();
            
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
            return "File content (exit code " + exitCode + "):\
" + output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟使用Runtime.exec的危险方式
    @GetMapping("/exec")
    public String execCommand(@RequestParam String cmd) {
        try {
            // 直接执行用户输入的命令
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", cmd}
            );
            
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
            return "Command output (exit code " + exitCode + "):\
" + output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}