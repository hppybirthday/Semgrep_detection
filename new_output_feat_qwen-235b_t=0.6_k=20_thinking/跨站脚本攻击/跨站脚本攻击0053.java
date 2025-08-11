package com.example.bigdata.dashboard;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.stream.Collectors;

@Controller
public class UserBehaviorController {
    private final SearchService searchService;
    private final AlertService alertService;

    public UserBehaviorController(SearchService searchService, AlertService alertService) {
        this.searchService = searchService;
        this.alertService = alertService;
    }

    @GetMapping("/search")
    @ResponseBody
    public String handleSearch(@RequestParam String query) {
        // 漏洞点：未对用户输入的query参数进行转义处理
        String searchResult = searchService.processSearch(query);
        String alertMessage = alertService.generateAlert(query);
        
        return String.format("<div class='search-result'>%s</div>" + 
                           "<div class='alert-message'>%s</div>",
                           searchResult, alertMessage);
    }
}

class SearchService {
    private final SearchRepository searchRepository;

    public SearchService(SearchRepository searchRepository) {
        this.searchRepository = searchRepository;
    }

    String processSearch(String query) {
        // 记录搜索日志（看似安全的操作）
        LogUtil.recordSearchQuery(query);
        
        // 模拟数据库查询
        List<String> results = searchRepository.search(query);
        
        // 构造搜索结果HTML
        return new SearchResultAssembler().assembleResult(results, query);
    }
}

class SearchResultAssembler {
    String assembleResult(List<String> results, String query) {
        // 漏洞点：直接拼接用户输入的query参数到HTML中
        StringBuilder html = new StringBuilder();
        html.append(String.format("<h3>搜索关键词: %s</h3>", query));
        html.append("<ul>");
        
        for (String result : results) {
            html.append(String.format("<li>%s</li>", result));
        }
        
        html.append("</ul>");
        return html.toString();
    }
}

class AlertService {
    String generateAlert(String query) {
        // 复杂的条件判断掩盖漏洞
        if (query == null || query.length() < 5) {
            return "";
        }
        
        // 漏洞点：未对query参数进行校验
        if (query.contains("alert") || query.contains("script")) {
            // 表面过滤但存在绕过可能
            return "检测到潜在威胁内容";
        }
        
        // 错误地认为只有包含特定关键字才存在风险
        return String.format("注意：包含敏感词[%s]", query);
    }
}

class LogUtil {
    static void recordSearchQuery(String query) {
        // 实际未对安全防护产生作用
        if (query != null && query.length() > 100) {
            System.out.println("Long query detected: " + query.substring(0, 50));
        }
    }
}

interface SearchRepository {
    List<String> search(String query);
}

// 模拟数据访问层
class JpaSearchRepository implements SearchRepository {
    @Override
    public List<String> search(String query) {
        // 模拟数据库返回结果
        return List.of("Result 1 for " + query, "Result 2 matching " + query);
    }
}