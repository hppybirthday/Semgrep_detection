package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@Controller
class CommentController {
    private final List<String> comments = new ArrayList<>();

    @GetMapping("/")
    public String showComments(Model model) {
        model.addAttribute("comments", comments);
        return "comments";
    }

    @PostMapping("/add")
    public String addComment(@RequestParam("comment") String comment, Model model) {
        // 漏洞点：直接存储用户输入
        comments.add(comment);
        model.addAttribute("comments", comments);
        return "comments";
    }
}

// templates/comments.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
// <h1>Comments</h1>
// <div th:each="comment : ${comments}">
//     <!-- 漏洞点：使用utext直接渲染用户输入 -->
//     <p th:utext="${comment}"></p>
// </div>
// <form action="/add" method="post">
//     <textarea name="comment"></textarea>
//     <button type="submit">Submit</button>
// </form>
// </body>
// </html>