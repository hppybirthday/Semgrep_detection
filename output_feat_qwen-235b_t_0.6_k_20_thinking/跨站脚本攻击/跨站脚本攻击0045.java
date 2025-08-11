package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class MathSimApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathSimApplication.class, args);
    }
}

@Controller
class SimulationController {
    private final Map<String, String> modelParams = new HashMap<>();

    @PostMapping("/configure")
    public String configureSimulation(@RequestParam String formula, Model model) {
        if (formula == null || formula.isEmpty()) {
            model.addAttribute("error", "Formula cannot be empty");
            model.addAttribute("rawInput", formula);
            return "errorPage";
        }

        // 模拟数学建模参数解析
        try {
            // 使用不安全的动态表达式解析（元编程漏洞）
            Object result = evaluateExpression(formula);
            modelParams.put("result", result.toString());
            return "simulationResult";
        } catch (Exception e) {
            // 将用户输入直接暴露在错误信息中
            model.addAttribute("error", "Invalid formula: " + e.getMessage());
            model.addAttribute("rawInput", formula);
            return "errorPage";
        }
    }

    // 模拟不安全的动态表达式求值（元编程风险）
    private Object evaluateExpression(String formula) {
        // 实际场景中可能调用GroovyShell或JavaScript引擎
        if (formula.contains("<") || formula.contains(">")) {
            throw new RuntimeException("Invalid characters in formula");
        }
        return "Simulated result for: " + formula;
    }
}

// Thymeleaf模板：errorPage.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Error</title></head>
// <body>
// <h2 th:text="${error}">Error message</h2>
// <!-- 不安全的用户输入回显 -->
// <div th:text="${rawInput}">User input will appear here</div>
// </body>
// </html>