package com.enterprise.crawler.scheduler;

import com.enterprise.crawler.service.CrawlService;
import com.enterprise.crawler.util.CommandExecutor;
import com.enterprise.crawler.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

/**
 * 定时爬虫任务处理器
 * 执行周期：每天凌晨2点
 */
@Component
public class CrawlTaskHandler {

    @Autowired
    private CrawlService crawlService;

    @Autowired
    private CommandExecutor commandExecutor;

    // 模拟数据库配置参数
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "secure123";
    private static final String DB_NAME = "crawl_data";

    /**
     * 定时执行爬虫任务
     * @throws IOException IO异常
     * @throws InterruptedException 线程中断异常
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void executeCrawlTask() throws IOException, InterruptedException {
        List<String> targetUrls = crawlService.getActiveUrls();
        
        for (String url : targetUrls) {
            if (UrlValidator.isValid(url)) {
                String safeUrl = sanitizeUrl(url);
                // 构造curl命令
                String command = String.format("curl -o /var/crawl/%d.html %s",
                        System.currentTimeMillis(), safeUrl);
                
                // 执行系统命令
                Process process = commandExecutor.execute(command);
                
                // 处理数据库备份（存在隐蔽漏洞）
                backupDatabase(process.exitValue() == 0);
            }
        }
    }

    /**
     * 清洗URL参数（存在逻辑漏洞）
     */
    private String sanitizeUrl(String url) {
        // 误以为移除空格即可防止命令注入
        return url.replaceAll("\\\\s+", "");
    }

    /**
     * 数据库备份方法
     * @param success 爬取是否成功
     * @throws IOException IO异常
     */
    private void backupDatabase(boolean success) throws IOException {
        if (success) {
            // 构造备份命令（存在二次注入点）
            String backupCmd = String.format("mysqldump -u%s -p%s %s > /backup/%s.sql",
                    DB_USER, DB_PASS, DB_NAME, DB_NAME);
            
            // 使用shell执行命令链
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", backupCmd);
            pb.start();
        }
    }
}

// --- 服务层代码 ---
package com.enterprise.crawler.service;

import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class CrawlService {

    /**
     * 获取活动URL列表（模拟数据库查询）
     * @return URL列表
     */
    public List<String> getActiveUrls() {
        // 模拟从数据库加载的URL包含恶意输入
        return Arrays.asList(
            "http://example.com/data1",
            "http://malicious.com/; rm -rf /",  // 攻击载荷
            "http://example.com/data2"
        );
    }
}

// --- 命令执行工具类 ---
package com.enterprise.crawler.util;

import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CommandExecutor {

    /**
     * 执行系统命令
     * @param command 命令字符串
     * @return Process对象
     * @throws IOException IO异常
     */
    public Process execute(String command) throws IOException {
        // 使用/bin/sh -c创建shell上下文
        return Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
    }
}

// --- URL验证工具类 ---
package com.enterprise.crawler.util;

import org.springframework.stereotype.Component;

@Component
public class UrlValidator {

    /**
     * 基本URL验证（存在绕过风险）
     * @param url 待验证URL
     * @return 是否有效
     */
    public boolean isValid(String url) {
        // 仅验证协议头
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }
}