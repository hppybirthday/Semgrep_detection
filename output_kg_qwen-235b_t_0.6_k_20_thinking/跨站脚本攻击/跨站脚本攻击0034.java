package com.example.demo;

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
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

class Comment {
    String content;
    public Comment(String content) {
        this.content = content;
    }
    public String getContent() {
        return content;
    }
}

@Controller
class CommentController {
    List<Comment> comments = new ArrayList<>();

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("comments", comments);
        return "index";
    }

    @PostMapping("/add")
    public String addComment(@RequestParam String comment, Model model) {
        // 错误：直接存储用户输入，未进行任何转义处理
        comments.add(new Comment(comment));
        model.addAttribute("comments", comments);
        return "index";
    }
}

// templates/index.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>XSS Demo</title></head>
// <body>
//     <h1>Comments:</h1>
//     <div th:each="comment : ${comments}">
//         <!-- 错误：使用非安全方式输出用户内容 -->
//         <div th:utext="${comment.content}"></div>
//         <hr>
//     </div>
//     <form action="/add" method="post">
//         <textarea name="comment"></textarea>
//         <button type="submit">Submit</button>
//     </form>
// </body>
// </html>