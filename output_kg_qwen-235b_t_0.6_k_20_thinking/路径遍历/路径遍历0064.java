package com.example.vulnerablecrawler;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.*;

/**
 * 网络爬虫示例，存在路径遍历漏洞
 * 模拟开发者错误处理URL路径转换
 */
public class VulnerableWebCrawler {
    // 基础存储目录
    private static final String BASE_DIR = "downloads";

    /**
     * 模拟爬虫下载方法
     * @param urlString 待下载的URL
     * @throws Exception 异常处理
     */
    public void downloadPage(String urlString) throws Exception {
        URL url = new URL(urlString);
        String host = url.getHost();
        String path = url.getPath();
        
        // 生成本地存储路径 - 存在漏洞的代码
        String localPath = BASE_DIR + "/" + host + path;
        
        // 元编程风格：动态构建文件路径
        Path savePath = Paths.get(localPath);
        
        // 创建目录结构
        if (!Files.exists(savePath.getParent())) {
            Files.createDirectories(savePath.getParent());
        }
        
        // 模拟下载内容写入
        try (BufferedWriter writer = Files.newBufferedWriter(savePath)) {
            writer.write("<!DOCTYPE html><html>Mock Content</html>");
        }
        
        System.out.println("文件已保存至: " + savePath.toAbsolutePath());
    }

    /**
     * 主方法用于演示
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请提供URL作为参数");
            return;
        }
        
        try {
            VulnerableWebCrawler crawler = new VulnerableWebCrawler();
            crawler.downloadPage(args[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/**
 * 漏洞分析：
 * 1. 问题出现在路径构造方式：
 *    localPath = BASE_DIR + "/" + host + path;
 *    直接拼接host和原始path，未对path进行任何安全校验
 * 2. 攻击者可通过构造如下的URL触发漏洞：
 *    http://example.com/../../../../etc/passwd
 *    这会导致实际路径变为：downloads/example.com/../../../../etc/passwd
 *    最终解析为系统/etc/passwd文件
 * 3. 元编程特征体现在动态构建路径，通过用户输入直接控制文件系统操作路径
 * 4. 危害：
 *    - 任意文件读写
 *    - 信息泄露
 *    - 潜在的远程代码执行
 */