package com.example.xsscrawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

/**
 * 漏洞说明：该爬虫直接将抓取的网页标题和内容拼接到生成的HTML报告中，
 * 未对用户输入进行HTML转义，导致反射型XSS漏洞
 */
public class VulnerableCrawler {
    private static final String TEMPLATE = "<html><head><title>Crawl Report</title></head><body>
<h1>Report for %s</h1>
<div class='results'>%s</div>
</body></html>";

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java VulnerableCrawler <url>");
            return;
        }
        
        try {
            String report = generateReport(args[0]);
            System.out.println(report);
        } catch (Exception e) {
            System.err.println("Crawling failed: " + e.getMessage());
        }
    }

    public static String generateReport(String targetUrl) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        Document doc = Jsoup.parse(response.body());
        
        // 元编程风格：动态提取网页元数据
        List<String> metadata = new ArrayList<>();
        Elements metaTags = doc.select("meta[name=description], meta[property^=og:]");
        for (Element meta : metaTags) {
            metadata.add(meta.attr("content"));
        }
        
        // 漏洞点：直接拼接用户输入内容
        String title = doc.title();  // 未转义的标题
        String content = doc.body().text();  // 未转义的文本内容
        
        // 构造包含XSS漏洞的HTML报告
        String reportContent = String.format("<h2>Page Title: %s</h2>\
<div>First 200 chars: %s...</div>\
<ul class='metadata'>",
                title, content.substring(0, Math.min(200, content.length())));

        for (String data : metadata) {
            reportContent += String.format("<li>%s</li>", data);  // 未转义的元数据
        }
        
        reportContent += "</ul>";
        return String.format(TEMPLATE, targetUrl, reportContent);
    }
}