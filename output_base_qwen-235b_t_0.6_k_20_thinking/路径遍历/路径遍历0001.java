import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class WebCrawlerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebCrawlerApplication.class, args);
    }

    @RequestMapping("/crawl")
    public String crawl(@RequestParam String url, @RequestParam String savePath) {
        try {
            // 模拟爬虫下载内容
            URL website = new URL(url);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(website.openStream()));
            
            // 危险的文件路径拼接
            String finalPath = "/var/www/html/downloads/" + savePath;
            BufferedWriter writer = new BufferedWriter(
                new FileWriter(finalPath));
            
            // 写入下载内容
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.newLine();
            }
            
            reader.close();
            writer.close();
            
            return "Content saved to " + finalPath;
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟日志记录功能
    private void logAccess(String path, String clientIp) {
        try {
            BufferedWriter logger = new BufferedWriter(
                new FileWriter("/var/log/webcrawler/access.log", true));
            logger.write(String.format("[%s] Accessed %s from %s\
", 
                new Date(), path, clientIp));
            logger.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}