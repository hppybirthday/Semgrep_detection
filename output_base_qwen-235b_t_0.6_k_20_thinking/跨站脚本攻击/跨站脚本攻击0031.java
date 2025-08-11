package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class VulnerableAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableAppApplication.class, args);
    }

    @Bean
    public CommentService commentService() {
        return new CommentService();
    }
}

@Controller
class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping("/comments")
    public String getComments(Model model) {
        model.addAttribute("comments", commentService.getAllComments());
        return "comments";
    }

    @PostMapping("/comments")
    public String addComment(@RequestParam String content, Model model) {
        commentService.addComment(content);
        return "redirect:/comments";
    }
}

class Comment {
    private final String content;

    public Comment(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

class CommentService {
    private final List<Comment> comments = new ArrayList<>();

    public void addComment(String content) {
        comments.add(new Comment(content));
    }

    public List<Comment> getAllComments() {
        return comments;
    }
}

// templates/comments.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Comments</title></head>
// <body>
// <h1>User Comments</h1>
// <div th:each="comment : ${comments}">
//     <div style="margin:10px;padding:10px;border:1px solid #ccc">
//         <!-- Vulnerable point: Unsanitized user input rendered directly -->
//         <div th:inline="text" th:text="${comment.content}"></div>
//     </div>
// </div>
// <form action="/comments" method="post">
//     <textarea name="content" required></textarea>
//     <button type="submit">Submit</button>
// </form>
// </body>
// </html>