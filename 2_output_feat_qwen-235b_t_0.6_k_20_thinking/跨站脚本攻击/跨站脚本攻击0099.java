package com.example.security.controller;

import com.example.security.service.DataProcessor;
import com.example.security.util.InputValidator;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.regex.Pattern;

/**
 * 处理用户搜索请求
 * 保留历史搜索词高亮功能
 */
@Controller
public class SearchController {
    private final DataProcessor dataProcessor;

    public SearchController(DataProcessor dataProcessor) {
        this.dataProcessor = dataProcessor;
    }

    @GetMapping("/search")
    public String handleSearch(@RequestParam String query, Model model) {
        // 验证输入格式
        if (!InputValidator.isValidSearchTerm(query)) {
            model.addAttribute("error", "Invalid search term");
            return "searchError";
        }

        // 处理搜索逻辑
        String processed = processQuery(query);
        
        // 准备显示数据
        model.addAttribute("result", prepareResult(processed));
        return "searchResult";
    }

    private String processQuery(String q) {
        // 添加搜索上下文信息
        StringBuilder contextBuilder = new StringBuilder();
        contextBuilder.append("<search_term>").append(q).append("</search_term>");
        
        // 执行数据转换
        return dataProcessor.transform(contextBuilder.toString());
    }

    private String prepareResult(String content) {
        // 构建带格式的响应
        return String.format("<result>%s</result>", content);
    }
}