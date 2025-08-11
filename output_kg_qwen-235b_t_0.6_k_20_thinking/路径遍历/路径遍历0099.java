import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.Date;

@SpringBootApplication
@RestController
public class VulnerableCrawlerApplication {
    private static final String BASE_DIR = "/var/www/html/crawler_data/";

    @GetMapping("/archive")
    public String archiveContent(@RequestParam String url) {
        try {
            URL targetUrl = new URL(url);
            String rawPath = targetUrl.getPath();
            String cleanPath = rawPath.startsWith("/") ? rawPath.substring(1) : rawPath;

            // 构建存储路径（存在漏洞）
            File storageDir = new File(BASE_DIR + targetUrl.getHost());
            storageDir.mkdirs();

            // 路径遍历漏洞点：未清理../序列
            File targetFile = new File(storageDir, cleanPath);
            
            // 记录访问时间
            try (BufferedWriter logWriter = new BufferedWriter(
                new FileWriter(new File(storageDir, "access.log"), true))) {
                logWriter.write(String.format("[%s] Accessed: %s -> %s%n", 
                    new Date(), url, targetFile.getAbsolutePath()));
            }

            // 下载并保存内容
            RestTemplate restTemplate = new RestTemplate();
            String content = restTemplate.getForObject(targetUrl.toString(), String.class);
            
            try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(targetFile))) {
                writer.write(String.format("<!-- Archived at %s -->\n", new Date()));
                writer.write(content);
            }

            return String.format("Content archived to: %s (%d bytes)", 
                targetFile.getAbsolutePath(), content.length());

        } catch (Exception e) {
            return String.format("Error archiving content: %s", e.getMessage());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApplication.class, args);
    }
}