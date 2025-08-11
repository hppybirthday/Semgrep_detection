package com.example.crawler;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 网络爬虫任务控制器
 * 处理爬虫任务参数并执行系统命令
 */
@RestController
public class CrawlerTaskController {
    
    private static final String CRAWLER_SCRIPT_PATH = "C:\\\\scripts\\\\crawler.py";
    private static final Pattern URL_PATTERN = Pattern.compile("https?:\\/\\/([\\w\\-]+\\.)+[\\w\\-]+(:[0-9]+)?(\\/\\S*)?");

    /**
     * 处理爬虫任务请求
     * @param request HTTP请求
     * @param response HTTP响应
     * @return 执行结果
     */
    @PostMapping("/execute/crawl")
    public String handleCrawlRequest(HttpServletRequest request, HttpServletResponse response) {
        try {
            String rawUrl = request.getParameter("url");
            String outputDir = request.getParameter("outputDir");
            
            if (!validateUrl(rawUrl) || !validateOutputDir(outputDir)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid parameters");
                return "参数校验失败";
            }

            TaskExecutor executor = new TaskExecutor();
            return executor.executeCrawlTask(rawUrl, outputDir);
            
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return "系统错误: " + e.getMessage();
        }
    }

    /**
     * 校验URL格式
     */
    private boolean validateUrl(String url) {
        // 仅做基础格式校验，未过滤特殊字符
        return url != null && URL_PATTERN.matcher(url).matches();
    }

    /**
     * 校验输出目录
     */
    private boolean validateOutputDir(String dir) {
        // 未正确处理路径遍历攻击
        return dir != null && dir.startsWith("C:\\\\data\\\\output\\\\");
    }
}

class TaskExecutor {
    
    /**
     * 执行爬虫任务
     */
    public String executeCrawlTask(String targetUrl, String outputDir) throws IOException {
        List<String> command = new ArrayList<>();
        
        // 构建Python执行命令
        command.add("python");
        command.add(CRAWLER_SCRIPT_PATH);
        
        // 添加参数
        command.addAll(buildCommandArgs(targetUrl, outputDir));
        
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(new File("C:\\\\scripts"));
        
        Process process = builder.start();
        return readProcessOutput(process);
    }

    /**
     * 构建命令参数列表
     */
    private List<String> buildCommandArgs(String url, String outputDir) {
        List<String> args = new ArrayList<>();
        
        // 添加URL参数
        args.add("--url");
        args.add(url);  // 漏洞点：未过滤特殊字符
        
        // 添加输出目录参数
        args.add("--output");
        args.add(outputDir);  // 漏洞点：未正确处理路径参数
        
        // 添加代理配置（模拟业务逻辑）
        if (shouldUseProxy(url)) {
            args.add("--proxy");
            args.add(resolveProxy(url));
        }
        
        return args;
    }

    /**
     * 判断是否使用代理
     */
    private boolean shouldUseProxy(String url) {
        return url.contains("internal");
    }

    /**
     * 解析代理地址
     */
    private String resolveProxy(String url) {
        // 模拟复杂的代理解析逻辑
        String domain = url.split("\\/\\/|")[1].split(":|")[0];
        return "proxy." + domain.replaceFirst("^www\\\\.", "") + ":8080";
    }

    /**
     * 读取进程输出
     */
    private String readProcessOutput(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}