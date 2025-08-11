package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api/comments")
public class CommentController {
    private List<Comment> comments = new ArrayList<>();

    public static void main(String[] args) {
        SpringApplication.run(CommentController.class, args);
    }

    @PostMapping
    public Comment addComment(@RequestBody Comment comment) {
        // 漏洞点：直接存储用户输入内容，未进行任何转义处理
        comments.add(comment);
        return comment;
    }

    @GetMapping
    public List<Comment> getComments() {
        // 漏洞点：直接返回原始用户输入内容
        return comments;
    }

    static class Comment {
        private String content;
        // 快速原型开发风格：直接暴露getter/setter
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }
}
// 启动后可通过curl测试：
// curl -X POST http://localhost:8080/api/comments -H "Content-Type: application/json" -d "{\\"content\\":\\"<script>alert('xss')</script>\\"}"
// curl http://localhost:8080/api/comments