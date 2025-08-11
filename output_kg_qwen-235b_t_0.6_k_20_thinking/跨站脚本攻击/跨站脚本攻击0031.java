package com.example.crawler;

import com.sun.net.httpserver.HttpServer;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

/**
 * 模拟存在XSS漏洞的网络爬虫系统
 */
public class VulnerableCrawler {
    static Map<String, String> crawledData = new HashMap<>();

    public static void main(String[] args) throws IOException {
        // 启动模拟Web服务器
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/crawl", new CrawlerHandler());
        server.createContext("/display", new DisplayHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }

    static class CrawlerHandler implements com.sun.net.httpserver.HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
            String url = exchange.getRequestURI().getQuery().replace("url=", "");
            try {
                Document doc = Jsoup.connect(url).get();
                Elements links = doc.select("a[href]");
                
                // 存储第一个链接的文本内容（存在漏洞）
                if (!links.isEmpty()) {
                    Element firstLink = links.first();
                    String key = "link_" + (crawledData.size() + 1);
                    crawledData.put(key, firstLink.text());
                    String response = "Crawled data stored: " + key;
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } catch (Exception e) {
                String response = "Error crawling: " + e.getMessage();
                exchange.sendResponseHeaders(500, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }

    static class DisplayHandler implements com.sun.net.httpserver.HttpHandler {
        @Override
        public void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
            StringBuilder html = new StringBuilder();
            html.append("<html><body><h1>Crawled Data:</h1>");
            
            // 显示存储的爬取数据（存在XSS漏洞）
            for (Map.Entry<String, String> entry : crawledData.entrySet()) {
                html.append("<div>")
                     .append("<strong>")
                     .append(entry.getKey())
                     .append("</strong>: ")
                     .append(entry.getValue())  // 这里未进行HTML转义
                     .append("</div>");
            }
            
            html.append("</body></html>");
            exchange.sendResponseHeaders(200, html.length());
            OutputStream os = exchange.getResponseBody();
            os.write(html.toString().getBytes());
            os.close();
        }
    }
}