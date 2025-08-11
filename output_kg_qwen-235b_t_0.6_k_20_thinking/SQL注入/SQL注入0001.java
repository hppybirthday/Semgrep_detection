package com.example.crawler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.jdbc.core.JdbcTemplate;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

@Component
public class VulnerableCrawler {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 模拟爬取网页内容并存储到数据库
    public void crawlAndStore(String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            CloseableHttpResponse response = httpClient.execute(request);
            
            if (response.getStatusLine().getStatusCode() == 200) {
                String html = EntityUtils.toString(response.getEntity());
                
                // 提取网页标题
                Pattern titlePattern = Pattern.compile("<title>(.*?)<\\/title>", Pattern.CASE_INSENSITIVE);
                Matcher titleMatcher = titlePattern.matcher(html);
                String title = titleMatcher.find() ? titleMatcher.group(1) : "N/A";
                
                // 提取正文内容
                Pattern contentPattern = Pattern.compile("<div class=\\"content\\">(.*?)<\\/div>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                Matcher contentMatcher = contentPattern.matcher(html);
                String content = contentMatcher.find() ? contentMatcher.group(1).replaceAll("<.*?>", "") : "N/A";
                
                // 存储到数据库（存在SQL注入漏洞）
                String sql = "INSERT INTO crawled_data (title, content, source_url) VALUES ('" 
                    + title + "', '" + content + "', '" + url + "')";
                jdbcTemplate.update(sql);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 数据库表创建语句
    /*
    CREATE TABLE crawled_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255),
        content TEXT,
        source_url VARCHAR(255)
    );
    */
}