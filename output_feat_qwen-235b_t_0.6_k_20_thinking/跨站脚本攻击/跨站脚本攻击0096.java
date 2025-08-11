package com.example.crawler.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.example.crawler.service.CrawlerService;
import com.example.crawler.exception.CrawlException;

@Controller
public class CrawlerController {
    
    @Autowired
    private CrawlerService crawlerService;

    @GetMapping("/crawl")
    public ModelAndView crawlPage(@RequestParam String url, @RequestParam String callback) {
        ModelAndView modelAndView = new ModelAndView("result");
        try {
            String content = crawlerService.fetchContent(url);
            modelAndView.addObject("content", content);
            modelAndView.addObject("callbackUrl", callback);
        } catch (CrawlException e) {
            modelAndView.addObject("error", "Failed to fetch URL: " + url + " with callback: " + callback);
            modelAndView.addObject("rawCallback", callback);
        }
        return modelAndView;
    }
}

// CrawlerService.java
package com.example.crawler.service;

import org.springframework.stereotype.Service;
import com.example.crawler.exception.CrawlException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@Service
public class CrawlerService {
    public String fetchContent(String urlString) throws CrawlException {
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            if (connection.getResponseCode() != 200) {
                throw new CrawlException("HTTP error code: " + connection.getResponseCode());
            }
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        } catch (Exception e) {
            throw new CrawlException("Crawl failed: " + e.getMessage(), e);
        }
    }
}

// result.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head>
    <title>Crawler Result</title>
</head>
<body>
    <h1>Crawled Content</h1>
    
    <div id="result">
        ${content}
    </div>
    
    <c:if test="${not empty error}">
        <div class="error" onclick="window.location.href='${rawCallback}'">
            ${error}
        </div>
    </c:if>
    
    <script>
        // 模拟前端回调逻辑
        if (window.location.href.includes('callback=')) {
            window.location.href = '${rawCallback}';
        }
    </script>
</body>
</html>