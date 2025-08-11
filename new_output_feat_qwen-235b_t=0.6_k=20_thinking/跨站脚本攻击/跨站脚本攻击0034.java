package com.example.app.controller;

import com.example.app.model.Comment;
import com.example.app.service.CommentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/comments")
public class CommentController {
    @Autowired
    private CommentService commentService;

    @GetMapping
    public String listComments(Model model) {
        List<Comment> comments = commentService.getAllComments();
        model.addAttribute("comments", comments);
        return "comments/list";
    }

    @PostMapping
    public String addComment(@RequestParam("content") String content) {
        Comment comment = new Comment();
        comment.setContent(stripUnsafeTags(content));
        commentService.saveComment(comment);
        return "redirect:/comments";
    }

    private String stripUnsafeTags(String input) {
        // 错误地认为移除script标签就足够安全
        return input.replace("<script>", "").replace("</script>", "");
    }
}

// Comment.java
package com.example.app.model;

public class Comment {
    private Long id;
    private String content;

    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

// CommentService.java
package com.example.app.service;

import com.example.app.model.Comment;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CommentService {
    private List<Comment> comments = new ArrayList<>();

    public List<Comment> getAllComments() {
        return comments;
    }

    public void saveComment(Comment comment) {
        // 模拟存储到数据库
        comment.setId((long) (comments.size() + 1));
        comments.add(comment);
    }
}

// Thymeleaf模板 comments/list.html
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Comments</title>
</head>
<body>
    <h1>User Comments</h1>
    <div th:each="comment : ${comments}">
        <p th:text="${comment.content}"></p> <!-- 漏洞点：直接输出用户输入内容 -->
    </div>
    
    <form action="/comments" method="post">
        <textarea name="content"></textarea>
        <button type="submit">Submit</button>
    </form>
</body>
</html>
*/