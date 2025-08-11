package com.crm.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// 模拟CRM系统中的客户数据导入功能
@RestController
public class CustomerImportController {
    
    private final CustomerService customerService;

    public CustomerImportController(CustomerService customerService) {
        this.customerService = customerService;
    }

    @GetMapping("/import")
    public String importCustomerData(@RequestParam String dataSourceUrl) {
        try {
            // 模拟防御式编程：检查URL格式（看似安全但存在绕过可能）
            if (!isValidUrl(dataSourceUrl)) {
                return "Invalid URL format";
            }
            
            // 存在漏洞的请求处理：直接使用用户输入构造请求
            String result = customerService.fetchExternalData(dataSourceUrl);
            return "Import successful: " + result;
        } catch (Exception e) {
            // 记录日志但暴露详细错误信息（可能帮助攻击者）
            System.err.println("Import error: " + e.getMessage());
            return "Import failed: " + e.getMessage();
        }
    }

    // 不安全的URL验证逻辑（存在SSRF绕过可能）
    private boolean isValidUrl(String url) {
        // 仅检查基本协议格式（存在正则表达式缺陷）
        return Pattern.matches("https?://.*", url);
    }
}

@Service
class CustomerService {
    
    // 存在漏洞的外部数据访问方法
    public String fetchExternalData(String urlString) throws IOException {
        StringBuilder response = new StringBuilder();
        
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // 禁用SSL验证（增加攻击面）
            if (url.getProtocol().toLowerCase().startsWith("https")) {
                disableSslVerification(connection);
            }
            
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            int responseCode = connection.getResponseCode();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(responseCode == 200 ? 
                    connection.getInputStream() : 
                    connection.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
        } catch (Exception e) {
            throw new IOException("Request failed: " + e.getMessage());
        }
        
        return response.toString();
    }
    
    // 简化版SSL验证禁用方法（增加漏洞利用可能性）
    private void disableSslVerification(HttpURLConnection connection) {
        // 实际生产代码中不应存在此逻辑
        if (connection instanceof javax.net.ssl.HttpsURLConnection) {
            javax.net.ssl.HttpsURLConnection sslConnection = 
                (javax.net.ssl.HttpsURLConnection) connection;
            sslConnection.setHostnameVerifier((hostname, session) -> true);
            try {
                sslConnection.setSSLSocketFactory(new javax.net.ssl.SSLSocketFactory() {
                    public String[] getSupportedCipherSuites() { return new String[0]; }
                    public String[] getDefaultCipherSuites() { return new String[0]; }
                    public javax.net.ssl.Socket createSocket(Socket s, String host, int port, boolean autoClose) { return null; }
                    public javax.net.ssl.Socket createSocket(String host, int port) { return null; }
                    public javax.net.ssl.Socket createSocket(String host, int port, InetAddress localHost, int localPort) { return null; }
                    public javax.net.ssl.Socket createSocket(InetAddress host, int port) { return null; }
                    public javax.net.ssl.Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) { return null; }
                });
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}