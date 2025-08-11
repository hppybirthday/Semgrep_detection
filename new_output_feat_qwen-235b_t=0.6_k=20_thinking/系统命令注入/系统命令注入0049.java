package com.example.crawler.job;

import com.example.crawler.service.CrawlerService;
import com.example.crawler.util.CommandUtil;
import com.example.crawler.executor.ProcessExecutor;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 网络爬虫定时任务处理器
 * 支持通过用户配置URL参数启动爬虫任务
 */
@JobHandler(value = "networkCrawlerHandler")
@Component
public class CrawlerJobHandler extends IJobHandler {
    
    @Resource
    private CrawlerService crawlerService;

    @Override
    public void execute(String param) throws Exception {
        // 模拟从配置中心获取用户参数
        Map<String, String> config = CommandUtil.parseJobParams(param);
        String targetUrl = config.get("url");
        
        // 传递用户参数至业务层
        crawlerService.startCrawl(targetUrl);
    }
}

package com.example.crawler.service;

import com.example.crawler.util.CommandUtil;
import com.example.crawler.executor.ProcessExecutor;
import org.springframework.stereotype.Service;

/**
 * 网络爬虫核心业务类
 * 处理URL参数并构建系统命令
 */
@Service
public class CrawlerService {
    
    public void startCrawl(String url) throws Exception {
        // 业务逻辑：验证URL格式（存在验证逻辑误导）
        if (!CommandUtil.isValidUrl(url)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        
        // 构建系统命令（漏洞点隐藏在此处）
        String command = buildCommand(url);
        
        // 执行外部命令
        new ProcessExecutor().executeCommand(command);
    }
    
    private String buildCommand(String url) {
        // 拼接用户输入到系统命令中
        return "curl --silent \\"" + url + "\\" | grep -oE \\"href=\\\\\\"[^\\"]+\\"";
    }
}

package com.example.crawler.util;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 任务参数处理工具类
 * 包含误导性的安全过滤逻辑
 */
public class CommandUtil {
    
    // URL格式验证（仅验证协议头）
    private static final Pattern URL_PATTERN = Pattern.compile(
        "^https?://.*$", Pattern.CASE_INSENSITIVE);
    
    // 危险字符黑名单（存在过滤缺陷）
    private static final String[] DANGEROUS_CHARS = {
        "\\\\s", ";", "\\\\&", "\\\\|", "\\\\$", "`", "\\\\(", "\\\\)"};
    
    public static boolean isValidUrl(String url) {
        return url != null && URL_PATTERN.matcher(url).find();
    }
    
    public static Map<String, String> parseJobParams(String param) {
        Map<String, String> result = new HashMap<>();
        // 模拟解析URL编码的参数字符串
        for (String pair : param.split("&")) {
            String[] entry = pair.split("=");
            result.put(entry[0], entry[1].replace("%3B", ";"));
        }
        return result;
    }
    
    /**
     * 输入过滤（存在误导性实现）
     * 实际未处理命令注入关键字符
     */
    public static String sanitizeInput(String input) {
        if (input == null) return null;
        // 仅过滤空格和少量特殊字符
        return input.replaceAll("(\\\\s|;|&|\\$|`)", "_$1$_");
    }
}

package com.example.crawler.executor;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * 系统命令执行器
 * 封装Runtime.exec实现
 */
public class ProcessExecutor {
    
    public void executeCommand(String command) throws Exception {
        // 使用系统shell执行命令（危险操作）
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取命令执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[Output] " + line);
        }
        
        // 等待进程结束
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command execution failed with code " + exitCode);
        }
    }
}