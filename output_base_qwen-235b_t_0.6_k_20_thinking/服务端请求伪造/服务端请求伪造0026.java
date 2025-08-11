package com.example.vulnerable;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/clean")
public class DataCleaner {
    
    // 模拟CSV数据清洗服务
    @GetMapping("/csv")
    public Map<String, Object> cleanCSV(@RequestParam String sourceUrl) {
        Map<String, Object> result = new HashMap<>();
        CloseableHttpClient httpClient = HttpClients.createDefault();
        
        try {
            // 漏洞点：直接使用用户输入的URL
            HttpGet request = new HttpGet(sourceUrl);
            CloseableHttpResponse response = httpClient.execute(request);
            
            if (response.getStatusLine().getStatusCode() == 200) {
                String csvData = EntityUtils.toString(response.getEntity());
                
                // 简单数据清洗逻辑
                String[] lines = csvData.split("\\\\r?\\\
");
                int validLines = 0;
                for (String line : lines) {
                    if (line.contains(",")) validLines++;
                }
                
                result.put("totalLines", lines.length);
                result.put("validLines", validLines);
                result.put("cleanRate", (double)validLines/lines.length);
                
            } else {
                result.put("error", "Failed to fetch data: " + response.getStatusLine());
            }
            
        } catch (Exception e) {
            result.put("error", "Exception: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { httpClient.close(); } catch (IOException e) {}
        }
        
        return result;
    }
    
    /*
     * 示例请求:
     * curl "http://localhost:8080/clean/csv?sourceUrl=https://example.com/data.csv"
     * 攻击示例:
     * curl "http://localhost:8080/clean/csv?sourceUrl=file:///etc/passwd"
     * curl "http://localhost:8080/clean/csv?sourceUrl=http://127.0.0.1:8080/internal_api"
     */
}