package com.crm.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/feedback")
public class FeedbackController {
    private List<String> feedbackList = new ArrayList<>();

    @GetMapping("/form")
    public String showForm() {
        return "feedback-form";
    }

    @PostMapping("/submit")
    public String submitFeedback(@RequestParam("content") String content, Model model) {
        // 漏洞点：直接存储用户输入内容
        feedbackList.add(content);
        model.addAttribute("message", "Feedback received!");
        return "feedback-success";
    }

    @GetMapping("/list")
    public String listFeedbacks(Model model) {
        // 漏洞点：直接输出用户输入内容到HTML
        StringBuilder html = new StringBuilder("<ul>");
        for (String feedback : feedbackList) {
            html.append("<li>").append(feedback).append("</li>"); // 未转义
        }
        html.append("</ul>");
        model.addAttribute("feedbackHtml", html.toString());
        return "feedback-list";
    }
}

// Thymeleaf模板 feedback-list.html:
// <div th:innerHTML="${feedbackHtml}"></div> // 漏洞点：使用innerHTML导致XSS

// 模拟实体类
class Feedback {
    private String content;
    // 未进行内容过滤
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}