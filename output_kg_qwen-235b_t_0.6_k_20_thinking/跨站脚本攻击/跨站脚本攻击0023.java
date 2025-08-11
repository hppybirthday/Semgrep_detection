package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@SpringBootApplication
public class XssApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssApplication.class, args);
    }
}

@Controller
class XssController {
    @GetMapping("/predict")
    public String showForm() {
        return "form";
    }

    @PostMapping("/predict")
    public String handlePrediction(@RequestParam("input") String input, Model model) {
        // 模拟机器学习预测过程
        String result = "预测结果: " + (input.contains("malicious") ? "恶意流量" : "正常流量");
        
        // 将用户输入直接传递给视图（存在漏洞）
        model.addAttribute("input", input);
        model.addAttribute("result", result);
        
        return "result";
    }
}

// Thymeleaf模板：resources/templates/result.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>XSS Demo</title></head>
// <body>
//   <h2 th:text="${result}"></h2>
//   <p>原始输入：<span th:utext="${input}"></span></p> <!-- 漏洞触发点 -->
//   <p>示例：尝试输入 <script>alert('xss')</script></p>
// </body>
// </html>