package com.example.vulnerablecrawler;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class VulnerableCrawler {
    @GetMapping("/fetch")
    @ResponseBody
    public String fetchContent(@RequestParam("url") String targetUrl, HttpServletResponse response) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            // 漏洞点：直接使用用户输入的URL发起请求
            HttpGet request = new HttpGet(targetUrl);
            CloseableHttpResponse httpResponse = httpClient.execute(request);
            HttpEntity entity = httpResponse.getEntity();
            
            if (entity != null) {
                String result = EntityUtils.toString(entity);
                // 设置响应头允许跨域（增加攻击面）
                response.setHeader("Access-Control-Allow-Origin", "*");
                return result;
            }
        } catch (Exception e) {
            return "Error fetching content: " + e.getMessage();
        } finally {
            try {
                httpClient.close();
            } catch (IOException e) {
                // 忽略关闭异常
            }
        }
        return "Empty response";
    }

    // 模拟内部管理接口（攻击目标）
    @GetMapping("/internal/admin/config")
    @ResponseBody
    private String getInternalConfig() {
        return "{\\"db_password\\":\\"admin123\\",\\"secret_key\\":\\"s3cr3t\\"}";
    }

    // 模拟元数据服务访问（云环境攻击面）
    @GetMapping("/metadata")
    @ResponseBody
    private String getMetadata() {
        return "http://169.254.169.254/latest/meta-data/";
    }
}