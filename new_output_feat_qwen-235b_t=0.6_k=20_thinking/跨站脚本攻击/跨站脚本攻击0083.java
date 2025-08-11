package com.example.mlsearch.controller;

import com.example.mlsearch.service.SearchService;
import com.example.mlsearch.util.SearchUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * 搜索控制器
 * @author dev
 * @date 2023-09-20
 */
@Controller
public class SearchController {
    private final SearchService searchService;

    public SearchController(SearchService searchService) {
        this.searchService = searchService;
    }

    @GetMapping("/search")
    public String performSearch(@RequestParam("keyword") String keyword, Model model) {
        if (SearchUtil.isValidQuery(keyword)) {
            List<String> results = searchService.search(keyword);
            String processedKeyword = SearchUtil.processQuery(keyword);
            model.addAttribute("results", results);
            model.addAttribute("keyword", processedKeyword);
            // 漏洞点：未对用户输入进行HTML编码
            model.addAttribute("debugInfo", "Last query: " + keyword);
        } else {
            model.addAttribute("error", "Invalid search term");
        }
        return "search_results";
    }
}

package com.example.mlsearch.service;

import com.example.mlsearch.util.SearchUtil;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 搜索业务逻辑
 * @author dev
 * @date 2023-09-20
 */
@Service
public class SearchService {
    public List<String> search(String query) {
        // 模拟数据库查询
        return List.of(
            "Result 1 for " + query,
            "Result 2 for " + query,
            "Result 3 for " + query
        );
    }
}

package com.example.mlsearch.util;

import org.springframework.util.StringUtils;

/**
 * 搜索工具类
 * @author dev
 * @date 2023-09-20
 */
public class SearchUtil {
    public static boolean isValidQuery(String query) {
        return StringUtils.hasText(query) && query.length() < 100;
    }

    public static String processQuery(String query) {
        // 误导性处理：仅替换空格
        return query.replace(" ", "_");
    }

    // 未使用的安全方法（误导性代码）
    @SuppressWarnings("unused")
    private static String sanitizeInput(String input) {
        return input.replaceAll("[<>]", "");
    }
}

// Thymeleaf模板（search_results.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Search Results</title>
</head>
<body>
    <h1>Search Results for <span th:text="${keyword}"></span></h1>
    <div th:if="${error}">
        <p th:text="${error}"></p>
    </div>
    <ul>
        <li th:each="result : ${results}"
            th:text="${result}">
        </li>
    </ul>
    <!-- 调试信息（漏洞点）-->
    <div id="debug" th:utext="${debugInfo}"></div>
</body>
</html>
*/