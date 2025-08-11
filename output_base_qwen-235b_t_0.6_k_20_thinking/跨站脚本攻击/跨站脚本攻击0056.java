import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ui.Model;

import java.util.Arrays;

@SpringBootApplication
public class MLApp {
    public static void main(String[] args) {
        SpringApplication.run(MLApp.class, args);
    }
}

@Controller
class MLController {
    // 模拟机器学习模型预测
    public String predictSentiment(String text) {
        // 简化版情感分析逻辑
        if (text.toLowerCase().contains("happy")) return "Positive";
        if (text.toLowerCase().contains("sad")) return "Negative";
        return "Neutral";
    }

    @PostMapping("/predict")
    public String predict(@RequestParam("input") String input, Model model) {
        // 漏洞点：未对用户输入进行转义直接传递给模板
        model.addAttribute("userInput", input);
        model.addAttribute("sentiment", predictSentiment(input));
        return "result";
    }
}

// templates/result.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>ML Result</title></head>
// <body>
//     <h2>Prediction Result</h2>
//     <p>User Input: <span th:text="${userInput}"></span></p>
//     <p>Sentiment: <span th:text="${sentiment}"></span></p>
//     <!-- 漏洞点：使用非安全方式显示用户输入 -->
//     <div th:utext="${'Raw HTML: ' + userInput}"></div>
// </body>
// </html>