package com.example.crawler.domain;

import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 网络爬虫服务 - 存在系统命令注入漏洞的实现
 */
public class VulnerableCrawlerService {
    
    private static final ExecutorService executor = Executors.newSingleThreadExecutor();
    
    /**
     * 爬取指定URL的内容
     * @param request 包含目标URL的爬取请求
     * @return 爬取结果
     * @throws IOException
     */
    public String crawl(CrawlRequest request) throws IOException {
        String url = request.getUrl();
        Process process = null;
        try {
            // 漏洞点：直接将用户输入拼接到命令中
            String[] cmd = {"sh", "-c", "curl " + url};
            process = Runtime.getRuntime().exec(cmd);
            
            // 异步处理错误流防止阻塞
            executor.submit(new StreamGobbler(process.getErrorStream()));
            
            // 读取标准输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            process.waitFor();
            return result.toString();
            
        } catch (Exception e) {
            throw new IOException("Crawl failed: " + e.getMessage());
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
    
    /**
     * 流处理线程类
     */
    private static class StreamGobbler implements Runnable {
        private final InputStream inputStream;

        public StreamGobbler(InputStream is) {
            this.inputStream = is;
        }

        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // 记录日志（漏洞点：未记录异常内容）
                    System.out.println("Error stream: " + line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

/**
 * 爬虫请求领域模型
 */
class CrawlRequest {
    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}

/**
 * 漏洞利用示例入口
 */
class CrawlerApplication {
    public static void main(String[] args) {
        VulnerableCrawlerService service = new VulnerableCrawlerService();
        CrawlRequest request = new CrawlRequest();
        
        // 模拟用户输入
        if (args.length > 0) {
            request.setUrl(args[0]);
        } else {
            // 默认测试值（包含恶意输入）
            request.setUrl("http://example.com; rm -rf /");
        }
        
        try {
            String result = service.crawl(request);
            System.out.println("Crawl result: " + result);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}