import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

@SpringBootApplication
public class VulnerableWebCrawler {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableWebCrawler.class, args);
    }

    @Controller
    class CrawlerController {
        @GetMapping("/crawl")
        public String crawl(@RequestParam String url, Model model) throws IOException {
            String content = new CrawlerService().fetchContent(url);
            model.addAttribute("content", content);
            return "result";
        }
    }

    static class CrawlerService {
        public String fetchContent(String urlString) throws IOException {
            StringBuilder content = new StringBuilder();
            URL url = new URL(urlString);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(url.openStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\
");
                }
            }
            return content.toString();
        }
    }
}

// templates/result.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Crawl Result</title></head>
// <body>
// <h1>Page Content:</h1>
// <div th:utext="${content}"></div>  // 漏洞点：未转义输出
// </body>
// </html>