package com.example.bigdata.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.example.bigdata.service.DataProcessingService;

@Controller
public class DataAnalysisController {
    private final DataProcessingService dataService = new DataProcessingService();

    @PostMapping("/process")
    public String processData(@RequestParam("data") String rawData, Model model) {
        try {
            String result = dataService.analyzeData(rawData);
            model.addAttribute("result", result);
            return "analysis_result";
        } catch (Exception e) {
            // 漏洞点：直接将原始输入包含在错误信息中
            String errorMsg = "数据处理失败: " + e.getMessage() + " [原始输入: " + rawData + "]";
            model.addAttribute("error", errorMsg);
            return "error_page";
        }
    }
}

// 模拟大数据处理服务类
package com.example.bigdata.service;

public class DataProcessingService {
    public String analyzeData(String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("输入为空");
        }
        
        // 模拟复杂的数据处理流程
        if (input.contains("<script>")) {
            throw new RuntimeException("非法脚本注入尝试");
        }
        
        // 漏洞点：未验证输入直接处理
        return "处理完成: " + input.substring(0, Math.min(50, input.length()));
    }
}

// Thymeleaf模板示例（error_page.html）
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <div class="error" th:text="${error}"></div>  // 安全写法
//   <div class="unsafe" th:utext="${error}"></div> // 危险写法
// </body>
// </html>
