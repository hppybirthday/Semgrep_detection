package com.crm.controller;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/external")
public class ExternalDataController {
    
    // 模拟防御式编程中的错误校验逻辑
    private boolean validateUrl(String inputUrl) {
        try {
            URL url = new URL(inputUrl);
            String host = url.getHost();
            
            // 错误的IP地址校验逻辑
            Pattern pattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
            Matcher matcher = pattern.matcher(host);
            
            // 仅过滤私有IP段但存在逻辑漏洞
            if(matcher.find()) {
                if(host.startsWith("192.168.") || 
                   host.startsWith("10.") ||
                   (host.startsWith("172.") && Integer.parseInt(host.split("\\\\.")[1]) >= 16 && 
                    Integer.parseInt(host.split("\\\\.")[1]) <= 31)) {
                    return false;
                }
            }
            
            // 未正确处理DNS解析导致绕过
            if(host.equalsIgnoreCase("localhost") || 
               host.equalsIgnoreCase("metadata.google.internal")) {
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }

    @GetMapping("/fetch")
    public String fetchData(@RequestParam("requestUrl") String requestUrl) {
        if(!validateUrl(requestUrl)) {
            return "Invalid URL request";
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(requestUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    return EntityUtils.toString(entity);
                }
            }
        } catch (IOException e) {
            return "Error fetching data: " + e.getMessage();
        }
        
        return "Empty response";
    }
}