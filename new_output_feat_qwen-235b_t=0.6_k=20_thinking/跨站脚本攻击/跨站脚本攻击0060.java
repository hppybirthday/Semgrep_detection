package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class SearchApplication {
    public static void main(String[] args) {
        SpringApplication.run(SearchApplication.class, args);
    }

    @Bean
    public SearchService searchService() {
        return new SearchService();
    }
}

@Controller
class SearchController {
    private final SearchService searchService;

    public SearchController(SearchService searchService) {
        this.searchService = searchService;
    }

    @GetMapping("/search")
    public String handleSearch(@RequestParam("keyword") String keyword, Model model) {
        List<String> results = new ArrayList<>();
        
        if (keyword != null && !keyword.isEmpty()) {
            // 模拟爬虫搜索结果
            results.add("Result for '" + keyword + "'");
            
            // 记录历史搜索
            searchService.recordSearch(keyword);
            
            // 处理高亮显示
            String highlighted = highlightKeyword(keyword);
            model.addAttribute("keyword", highlighted);
        }
        
        model.addAttribute("results", results);
        return "search_results";
    }

    private String highlightKeyword(String keyword) {
        // 错误：直接拼接HTML标签
        return "<span class='highlight'>" + keyword + "</span>";
    }
}

class SearchService {
    private final List<String> searchHistory = new ArrayList<>();

    void recordSearch(String keyword) {
        if (searchHistory.size() > 100) {
            searchHistory.remove(0);
        }
        
        // 存储原始输入
        searchHistory.add(keyword);
    }

    List<String> getRecentSearches() {
        return new ArrayList<>(searchHistory);
    }
}

// templates/search_results.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <div th:each="result : ${results}">
//         <p th:utext="${result}"></p> <!-- 不安全的HTML渲染 -->
//     </div>
//     <div th:if="${not #lists.isEmpty(recentSearches)}">
//         <h3>Recent Searches:</h3>
//         <ul>
//             <li th:each="search : ${recentSearches}"
//                 th:text="${search}"></li>
//         </ul>
//     </div>
// </body>
// </html>