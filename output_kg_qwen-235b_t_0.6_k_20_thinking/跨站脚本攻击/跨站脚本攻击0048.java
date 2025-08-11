package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

@SpringBootApplication
public class XssVulnerableApp {
    static class Comment {
        final String author;
        final String content;
        
        Comment(String author, String content) {
            this.author = author;
            this.content = content;
        }
    }

    @Controller
    static class CommentController {
        static List<Comment> comments = new ArrayList<>();

        @GetMapping("/comments")
        String getComments(Model model) {
            model.addAttribute("comments", comments);
            return "comments";
        }

        @PostMapping("/comments")
        String addComment(@RequestParam String author, @RequestParam String content) {
            // Vulnerable: No input sanitization
            comments.add(new Comment(author, content));
            return "redirect:/comments";
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }
}

// templates/comments.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Comments</title></head>
// <body>
//     <h1>User Comments</h1>
//     <div th:each="comment : ${comments}">
//         <p><b th:text="${comment.author}"></b>: 
//         <!-- Vulnerable: Raw HTML output -->
//         <span th:utext="${comment.content}"></span></p>
//     </div>
//     <form method="post" action="/comments">
//         <input name="author" placeholder="Your name">
//         <input name="content" placeholder="Your comment">
//         <button type="submit">Post</button>
//     </form>
// </body>
// </html>