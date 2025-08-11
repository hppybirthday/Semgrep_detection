package com.example.vulnerablecrawler;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.Scanner;

public interface Crawler {
    void crawl(String url) throws Exception;
}

abstract class AbstractCrawler implements Crawler {
    protected String sanitizeInput(String input) {
        // 错误的清理逻辑：只替换了一次../
        return input.replace("../", "");
    }
}

class FileCrawler extends AbstractCrawler {
    private final String baseDirectory;

    public FileCrawler(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    @Override
    public void crawl(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        String path = url.getPath();
        
        // 漏洞点：直接拼接用户控制的路径
        Path localPath = Paths.get(baseDirectory, path);
        
        // 创建目标目录结构
        Files.createDirectories(localPath.getParent());
        
        // 模拟下载文件内容
        try (InputStream in = url.openStream();
             OutputStream out = Files.newOutputStream(localPath)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
        
        System.out.println("Downloaded to: " + localPath.toString());
    }
}

public class VulnerableWebCrawler {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java VulnerableWebCrawler <url>");
            return;
        }
        
        try {
            // 初始化爬虫（基础目录为当前工作目录）
            Crawler crawler = new FileCrawler(System.getProperty("user.dir"));
            
            // 执行爬取（未验证输入）
            crawler.crawl(args[0]);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}