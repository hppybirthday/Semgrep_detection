package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssMlDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(XssMlDemoApplication.class, args);
    }
}

@Controller
class TextAnalysisController {
    
    // 模拟机器学习模型
    static class SimpleMLModel {
        List<String> analyze(String input) {
            List<String> result = new ArrayList<>();
            // 模拟文本处理：拆分关键词（实际场景可能更复杂）
            if (input != null && !input.isEmpty()) {
                String[] words = input.split(" ");
                for (String word : words) {
                    result.add(word);
                }
            }
            return result;
        }
    }
    
    @GetMapping("/analyze")
    public String showForm() {
        return "analyze-form";
    }
    
    @PostMapping("/analyze")
    public String processInput(@RequestParam("userText") String userText, Model model) {
        SimpleMLModel modelInstance = new SimpleMLModel();
        // 存在漏洞的代码：直接传递原始用户输入
        model.addAttribute("inputText", userText);
        model.addAttribute("keywords", modelInstance.analyze(userText));
        return "analysis-result";
    }
}

// analyze-form.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Text Analyzer</title></head>
// <body>
// <h2>Enter Text for Analysis</h2>
// <form action="/analyze" method="post">
//     <textarea name="userText" rows="4" cols="50"></textarea><br>
//     <input type="submit" value="Analyze">
// </form>
// </body>
// </html>

// analysis-result.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Analysis Result</title></head>
// <body>
// <h2>Analysis Result</h2>
// <!-- 存在漏洞的代码：直接显示原始用户输入 -->
// <p><strong>Your Input:</strong> ${inputText}</p>
// <h3>Keywords:</h3>
// <ul>
//   <li th:each="keyword : ${keywords}" th:text="${keyword}"></li>
// </ul>
// <a href="/analyze">Try Again</a>
// </body>
// </html>