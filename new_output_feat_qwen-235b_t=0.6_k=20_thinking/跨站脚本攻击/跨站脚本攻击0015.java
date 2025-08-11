package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @Bean
    public Filter analyticsFilter() {
        return new AnalyticsFilter();
    }
}

@Controller
class SearchController {
    private final SearchService searchService;

    public SearchController(SearchService searchService) {
        this.searchService = searchService;
    }

    @GetMapping("/search")
    public String search(@RequestParam String keyword, Model model) {
        model.addAttribute("keyword", keyword);
        searchService.processKeyword(keyword);
        return "searchResults";
    }
}

class SearchService {
    private final List<String> searchHistory = new ArrayList<>();

    public void processKeyword(String keyword) {
        if (keyword.length() > 50) {
            keyword = keyword.substring(0, 50);
        }
        searchHistory.add(keyword);
        // 模拟爬虫处理逻辑
        new CrawledContentProcessor().process(keyword);
    }
}

class CrawledContentProcessor {
    void process(String content) {
        // 模拟内容处理链
        String processed = new ContentNormalizer().normalize(content);
        new SearchResultIndexer().index(processed);
    }
}

class ContentNormalizer {
    String normalize(String content) {
        // 存在误导性的安全处理
        return content.replace("<b>", "<strong>").replace("</b>", "</strong>");
    }
}

class SearchResultIndexer {
    void index(String content) {
        // 模拟存储到内存索引
        InMemorySearchIndex.add(content);
    }
}

class InMemorySearchIndex {
    private static final List<String> index = new ArrayList<>();

    static void add(String content) {
        index.add(content);
    }

    static List<String> search(String query) {
        return new ArrayList<>(index);
    }
}

class AnalyticsFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        StringWriter writer = new StringWriter();
        MonitoringResponseWrapper responseWrapper = 
            new MonitoringResponseWrapper(response, writer);

        filterChain.doFilter(request, responseWrapper);

        String originalContent = writer.toString();
        String injectedContent = injectAnalyticsScript(originalContent, request);
        response.getWriter().write(injectedContent);
    }

    private String injectAnalyticsScript(String content, HttpServletRequest request) {
        String callback = request.getParameter("callback");
        if (callback == null || callback.isEmpty()) {
            return content;
        }
        // 漏洞点：直接拼接用户输入
        String script = "<script>document.write('" + callback + "');</script>";
        return content.replace("</body>", script + "</body>");
    }
}

class MonitoringResponseWrapper extends HttpServletResponseWrapper {
    private final StringWriter stringWriter = new StringWriter();

    public MonitoringResponseWrapper(HttpServletResponse response, StringWriter writer) {
        super(response);
    }

    @Override
    public java.io.PrintWriter getWriter() {
        return new java.io.PrintWriter(stringWriter);
    }

    public String getcontentAsString() {
        return stringWriter.toString();
    }
}