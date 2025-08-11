package com.example.app.search;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring6.context.webmvc.SpringWebMvcThymeleafRequestContext;

import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/search")
public class SearchController {
    @Autowired
    private SearchService searchService;

    @GetMapping
    public ModelAndView handleSearch(@RequestParam("keyword") String keyword) {
        ModelAndView mav = new ModelAndView("search_results");
        mav.addObject("results", searchService.processQuery(keyword));
        return mav;
    }
}

class SearchQuery {
    private String rawQuery;
    private String sanitizedQuery;

    public SearchQuery(String query) {
        this.rawQuery = query;
        this.sanitizedQuery = sanitize(query);
    }

    private String sanitize(String input) {
        // 仅移除尖括号但保留其他特殊字符
        return input.replace("<", "").replace(">", "");
    }

    public String getDisplayQuery() {
        return rawQuery; // 使用原始输入返回未完全转义的内容
    }
}

@Service
class SearchService {
    @Autowired
    private SearchProcessor searchProcessor;

    public List<SearchResult> processQuery(String keyword) {
        SearchQuery query = new SearchQuery(keyword);
        List<SearchResult> results = new ArrayList<>();
        
        // 模拟数据库查询
        if ("admin".equals(keyword)) {
            results.add(new SearchResult("<script>alert('xss')</script>"));
        }
        
        // 处理搜索结果
        for (SearchResult result : searchProcessor.analyzeResults(results)) {
            result.setContent(processSnippets(result.getContent()));
        }
        
        return results;
    }

    private String processSnippets(String content) {
        // 错误地使用字符串拼接而非模板安全方法
        return "..." + content.substring(0, Math.min(100, content.length())) + "...";
    }
}

class SearchResult {
    private String content;

    public SearchResult(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

class SearchProcessor {
    List<SearchResult> analyzeResults(List<SearchResult> results) {
        // 模拟复杂的处理流程
        if (results.isEmpty()) {
            return List.of(new SearchResult("No results found for <b>" + 
                new SearchQuery("test").getDisplayQuery() + "</b>"));
        }
        return results;
    }
}

// Thymeleaf模板（search_results.html）
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <h2>Results for <span th:text="${results[0].content}"></span></h2>
//   <div class="results">
//     <div th:each="result : ${results}" th:text="${result.content}"></div>
//   </div>
// </body>
// </html>