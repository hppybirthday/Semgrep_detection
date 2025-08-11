import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@SpringBootApplication
public class VulnerableCrawler {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawler.class, args);
    }

    @RestController
    public class CrawlerController {
        private final RestTemplate restTemplate = new RestTemplate();

        @PostMapping("/fetch")
        public ResponseEntity<String> fetchContent(@RequestParam String url) {
            // 漏洞点：直接使用用户输入的URL进行请求
            URI targetUri = URI.create(url);
            
            // 模拟爬虫行为，直接请求用户指定地址
            ResponseEntity<String> response = restTemplate.getForEntity(targetUri, String.class);
            
            // 返回爬取内容（可能暴露内部数据）
            return ResponseEntity.ok("\\"status\\":\\"success\\",\\"content\\":\\"" + response.getBody() + "\\"");
        }

        // 存在缺陷的过滤方法（被绕过）
        private boolean isAllowedHost(String host) {
            // 错误的白名单验证（仅检查开头）
            return host.startsWith("example.com") || host.startsWith("safe.org");
        }

        // 未使用的防御代码（容易被忽略）
        @Deprecated
        private String sanitizeUrl(String url) {
            // 应该包含完整的URL验证逻辑
            return url;
        }
    }

    // 配置类（声明式配置）
    @Configuration
    public class AppConfig {
        // 模拟声明式配置（实际未启用）
        @Bean
        public RestTemplate secureRestTemplate() {
            return new RestTemplate();
        }
    }
}