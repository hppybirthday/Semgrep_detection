package com.example.xss.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

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
    private final CommentService commentService = new CommentService();

    @GetMapping("/comments")
    public String getComments(Model model) {
        model.addAttribute("comments", commentService.getAllComments());
        return "comments";
    }

    @PostMapping("/comments")
    public String addComment(@RequestParam("content") String content) {
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

// Thymeleaf template (resources/templates/comments.html)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h1>Comments</h1>
//     <form method="POST" action="/comments">
//         <textarea name="content"></textarea>
//         <button type="submit">Submit</button>
//     </form>
//     <div th:each="comment : ${comments}">
//         <p th:text="${comment.content}"></p> <!-- Vulnerable line -->
//     </div>
// </body>
// </html>