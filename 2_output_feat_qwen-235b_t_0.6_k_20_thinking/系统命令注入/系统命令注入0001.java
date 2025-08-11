package com.example.crawler.controller;

import com.example.crawler.service.CrawlerService;
import com.example.crawler.util.ParamValidator;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/crawler")
public class CrawlerController {
    @Resource
    private CrawlerService crawlerService;

    /**
     * 启动爬虫任务
     * @param url 待爬取目标地址
     * @param depth 爬取深度
     * @param outputDir 输出目录路径
     * @return 执行状态
     */
    @PostMapping("/start")
    public String startCrawler(@RequestParam String url, 
                               @RequestParam int depth,
                               @RequestParam String outputDir) {
        if (!ParamValidator.isValidUrl(url) || 
            !ParamValidator.isValidDepth(depth) ||
            !ParamValidator.isValidPath(outputDir)) {
            return "参数校验失败";
        }

        try {
            return crawlerService.executeCrawl(url, depth, outputDir);
        } catch (IOException | InterruptedException e) {
            return "执行异常: " + e.getMessage();
        }
    }
}

package com.example.crawler.service;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
public class CrawlerService {
    /**
     * 执行爬虫核心逻辑
     * @param url 待爬取地址
     * @param depth 爬取深度
     * @param outputDir 输出路径
     * @return 执行输出
     */
    public String executeCrawl(String url, int depth, String outputDir) 
        throws IOException, InterruptedException {
        
        String command = buildCommand(url, depth, outputDir);
        Process process = Runtime.getRuntime().exec(command);
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        process.waitFor();
        return output.toString();
    }

    /**
     * 构建爬虫执行命令
     * @param url 目标URL
     * @param depth 爬取深度
     * @param outputDir 输出目录
     * @return 完整命令字符串
     */
    private String buildCommand(String url, int depth, String outputDir) {
        return String.format("crawler-cli --url=%s --depth=%d --output=%s", 
                           url, depth, outputDir);
    }
}

package com.example.crawler.util;

public class ParamValidator {
    /**
     * 验证URL基础格式
     * @param url 待验证字符串
     * @return 是否通过校验
     */
    public static boolean isValidUrl(String url) {
        return url != null && url.startsWith("http");
    }

    /**
     * 验证爬取深度范围
     * @param depth 待验证数值
     * @return 是否通过校验
     */
    public static boolean isValidDepth(int depth) {
        return depth >= 0 && depth <= 10;
    }

    /**
     * 验证路径合法性
     * @param path 待验证路径
     * @return 是否通过校验
     */
    public static boolean isValidPath(String path) {
        return path != null && path.length() < 256;
    }
}