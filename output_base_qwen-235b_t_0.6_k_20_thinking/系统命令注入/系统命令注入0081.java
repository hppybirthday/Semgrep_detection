import java.io.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class VulnerableCrawler {
    
    @GetMapping("/crawl")
    public String handleCrawl(String url) {
        try {
            // 模拟爬虫执行外部命令下载页面
            String command = String.format("curl -s %s", url);
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 等待进程结束
            int exitCode = process.waitFor();
            return String.format("Exit code: %d\
Output:\
%s", exitCode, output);
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawler.class, args);
    }
}

// 漏洞触发示例：
// curl "http://localhost:8080/crawl?url=; rm -rf /tmp/test"
// 将导致任意命令执行