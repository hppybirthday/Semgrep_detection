package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@RestController
public class XssDemoApplication {
    private static List<Comment> comments = new ArrayList<>();

    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }

    @PostMapping("/comment")
    public String addComment(@RequestParam String content) {
        comments.add(new Comment(content));
        return "Comment added";
    }

    @GetMapping("/get-comments")
    public String getComments() {
        StringBuilder html = new StringBuilder("<div class='comments'>");
        for (Comment comment : comments) {
            // 漏洞点：直接拼接用户输入内容
            html.append("<div class='comment'>").append(comment.content).append("</div>");
        }
        html.append("</div>");
        return html.toString();
    }

    static class Comment {
        String content;
        Comment(String content) { this.content = content; }
    }
}