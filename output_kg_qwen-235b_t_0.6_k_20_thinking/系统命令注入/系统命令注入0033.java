package com.example.crawler;

import java.io.*;
import java.util.Arrays;
import java.util.Scanner;

/**
 * 网络爬虫示例 - 存在系统命令注入漏洞
 * 模拟真实场景中使用系统命令下载网页内容时的漏洞
 */
public class VulnerableWebCrawler {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入要爬取的URL: ");
        String userInput = scanner.nextLine();
        
        try {
            // 漏洞点：直接将用户输入拼接到系统命令中
            String command = "curl -o output.html " + userInput;
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("下载内容: " + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("爬取完成，退出代码: " + exitCode);
            
        } catch (Exception e) {
            System.err.println("爬取失败: " + e.getMessage());
        }
    }
}

/*
漏洞利用示例：
正常输入: https://example.com
恶意输入: https://example.com; rm -rf /
攻击者可通过分号注入额外命令，导致系统文件被删除
*/