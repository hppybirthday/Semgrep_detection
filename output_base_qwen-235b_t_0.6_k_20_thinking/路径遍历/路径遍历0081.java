import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;

@SpringBootApplication
public class VulnerableCrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApplication.class, args);
    }
}

@RestController
class FileDownloadController {
    
    @GetMapping("/download")
    public ResponseEntity<String> downloadFile(@RequestParam("filename") String filename) {
        try {
            // 模拟爬虫配置文件读取
            String basePath = "/var/www/html/files/";
            File file = new File(basePath + filename);
            
            // 漏洞点：未验证用户输入
            if (!file.exists()) {
                return ResponseEntity.notFound().build();
            }
            
            // 读取文件内容
            StringBuilder content = new StringBuilder();
            FileReader reader = new FileReader(file);
            int c;
            while ((c = reader.read()) != -1) {
                content.append((char) c);
            }
            reader.close();
            
            return ResponseEntity.ok(content.toString());
            
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Error reading file");
        }
    }
    
    // 模拟爬虫任务接口
    @GetMapping("/crawl")
    public ResponseEntity<String> startCrawl(@RequestParam("url") String url) {
        // 实际爬虫逻辑省略
        return ResponseEntity.ok("Crawling: " + url);
    }
}