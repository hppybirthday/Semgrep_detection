package com.example.xss.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@Controller
public class GuestbookController {
    private List<String> messages = new ArrayList<>();

    @GetMapping("/guestbook")
    public String showGuestbook(@RequestParam(name = "msg", required = false) String message, Model model) {
        if (message != null && !message.isEmpty()) {
            // 漏洞点：直接存储用户输入内容
            messages.add(message);
        }
        
        // 漏洞点：未转义直接传递给视图
        model.addAttribute("messages", messages);
        return "guestbook";
    }
}

// src/main/resources/templates/guestbook.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head>
//     <title>Guestbook</title>
// </head>
// <body>
// <h1>Guestbook Messages</h1>
// <div th:each="msg : ${messages}">
//     <p th:text="${msg}"></p>  <!-- 漏洞点：直接输出未过滤的内容 -->
// </div>
// 
// <form method="get" action="/guestbook">
//     <textarea name="msg"></textarea>
//     <button type="submit">Post Message</button>
// </form>
// </body>
// </html>