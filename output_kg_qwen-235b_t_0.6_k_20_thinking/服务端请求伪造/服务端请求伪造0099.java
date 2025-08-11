import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class VulnerableCrawler {

    private final WebClient webClient;

    public VulnerableCrawler(WebClient.Builder builder) {
        this.webClient = builder.build();
    }

    @Bean
    public WebClient webClient(WebClient.Builder builder) {
        return builder.build();
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawler.class, args);
    }

    @GetMapping("/crawl")
    public String handleCrawl(@RequestParam String url) {
        try {
            // 使用反射动态构造请求方法
            Method method = this.getClass().getMethod("fetchContent", String.class);
            Object result = method.invoke(this, url);
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getCause().getMessage();
        }
    }

    public String fetchContent(String targetUrl) throws Exception {
        // 元编程特性：动态解析URL参数
        Map<String, Object> params = new HashMap<>();
        params.put("url", targetUrl);
        
        // 直接使用用户输入构造URI
        URI uri = new URI((String) params.get("url"));
        
        // 未验证目标地址的SSRF漏洞点
        return webClient.get()
            .uri(uri)
            .retrieve()
            .bodyToMono(String.class)
            .block();
    }
}