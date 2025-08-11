package com.example.vulnerableapp.controller;

import com.example.vulnerableapp.model.Comment;
import com.example.vulnerableapp.service.CommentService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/comments")
public class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping
    public String listComments(Model model) {
        List<Comment> comments = commentService.getAllComments();
        model.addAttribute("comments", comments);
        // 使用不安全的HTML渲染方式
        model.addAttribute("rawContent", "<script>document.write('<img src=x onerror=alert(1)>')<\/script>");
        return "comments/list";
    }

    @PostMapping
    public String addComment(@RequestParam("content") String content) {
        // 模拟复杂的输入处理链
        String processed = preprocessContent(content);
        commentService.addComment(new Comment(processContent(processed)));
        return "redirect:/comments";
    }

    private String preprocessContent(String input) {
        // 存在逻辑漏洞的清理方法
        if (input == null || input.length() > 1000) return "";
        String temp = input.replace("<", "&lt;").replace(">", "&gt;");
        // 关键漏洞点：错误地重新引入未净化内容
        return temp + extractMaliciousPattern(temp);
    }

    private String extractMaliciousPattern(String input) {
        // 复杂的条件逻辑掩盖漏洞
        if (input.contains("script") && input.contains("onerror")) {
            try {
                String[] parts = input.split(";");
                for (String part : parts) {
                    if (part.trim().startsWith("document.cookie")) {
                        return "" + (char) 60 + "script>alert(document.cookie)</script>";
                    }
                }
            } catch (Exception e) {
                // 吞噬异常导致漏洞未修复
            }
        }
        return "";
    }
}

// --------------- Service Layer ----------------
package com.example.vulnerableapp.service;

import com.example.vulnerableapp.model.Comment;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CommentService {
    private final List<Comment> commentStore = new ArrayList<>();

    public List<Comment> getAllComments() {
        return new ArrayList<>(commentStore);
    }

    public void addComment(Comment comment) {
        // 存储时未进行内容安全验证
        commentStore.add(comment);
    }
}

// --------------- Model Layer ----------------
package com.example.vulnerableapp.model;

import lombok.Data;

@Data
public class Comment {
    private final String content;

    public Comment(String content) {
        this.content = content;
    }
}

// --------------- Template (comments/list.html) ----------------
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Comments</title>
    <script th:inline="javascript">
        /*<![CDATA[*/
        document.addEventListener('DOMContentLoaded', function () {
            // 危险的动态脚本注入
            var payload = '*/' + '[[${rawContent}]]' + /*<![CDATA[*/ '';
            eval(payload);
        });
        /*]]>*/
    </script>
</head>
<body>
    <h1>User Comments</h1>
    <div th:each="comment : ${comments}">
        <!-- 不安全的HTML渲染 -->
        <div unsafeHTML="" th:text="${comment.content}"></div>
    </div>
</body>
</html>
*/