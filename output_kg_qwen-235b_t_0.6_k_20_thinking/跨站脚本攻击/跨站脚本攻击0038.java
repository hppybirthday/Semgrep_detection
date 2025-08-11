package com.example.bigdata.xss;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
public class XssVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }
}

@Controller
@RequestMapping("/analytics")
class AnalyticsController {
    
    @GetMapping("/search")
    @ResponseBody
    public String search(@RequestParam String query) {
        // 模拟大数据处理流程
        List<String> results = processData(query);
        
        // 构建HTML响应（存在XSS漏洞）
        StringBuilder html = new StringBuilder();
        html.append("<h2>Search Results for: ").append(query).append("</h2>");
        html.append("<ul>");
        for (String result : results) {
            html.append("<li>").append(result).append("</li>");
        }
        html.append("</ul>");
        return html.toString();
    }

    private List<String> processData(String query) {
        // 模拟大数据处理：过滤和转换
        return Arrays.asList("BigData1", "Analytics2", "Report3", "Dashboard4")
                   .stream()
                   .filter(s -> s.contains(query))
                   .map(s -> "Processed_" + s + "_Vulnerable")
                   .collect(Collectors.toList());
    }
}

// 注意：
// 1. 未对用户输入query进行HTML转义
// 2. 在HTML响应中直接拼接用户输入
// 3. 搜索结果直接渲染到页面