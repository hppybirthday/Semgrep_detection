package com.example.ssrf.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

@SpringBootApplication
@RestController
@RequestMapping("/api/files")
public class FileProxyApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileProxyApplication.class, args);
    }

    @PostMapping("/proxy")
    public String proxyFile(@RequestBody String externalUrl) {
        try {
            FileDownloader downloader = new FileDownloader();
            return downloader.download(externalUrl);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    static class FileDownloader {
        String download(String urlString) throws IOException {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            if (connection.getResponseCode() != 200) {
                throw new IOException("Failed to download file: " + connection.getResponseCode());
            }

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );
            StringBuilder content = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            
            reader.close();
            connection.disconnect();
            return content.toString();
        }
    }

    @Component
    static class SecurityConfig {
        // 模拟安全配置但未实现URL校验
        boolean validateUrl(String url) {
            // 错误地仅检查非空
            return url != null && !url.isEmpty();
        }
    }

    @Service
    static class FileProcessingService {
        String processFile(String url) {
            // 直接传递用户输入到下载器
            try {
                return new FileDownloader().download(url);
            } catch (Exception e) {
                return "Processing failed: " + e.getMessage();
            }
        }
    }
}