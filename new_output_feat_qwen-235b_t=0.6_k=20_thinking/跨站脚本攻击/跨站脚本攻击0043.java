package com.example.app.controller;

import com.example.app.model.Comment;
import com.example.app.service.CommentService;
import com.example.app.util.XssSanitizer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequiredArgsConstructor
@RequestMapping("/comments")
public class CommentController {
    private final CommentService commentService;
    private final XssSanitizer xssSanitizer;

    @GetMapping
    public String listComments(Model model) {
        List<Comment> comments = commentService.getAllComments();
        model.addAttribute("comments", comments);
        return "comments/list";
    }

    @PostMapping("/add")
    public String addComment(@RequestParam String content, 
                           @RequestParam String username) {
        String sanitizedContent = xssSanitizer.sanitize(content);
        commentService.addComment(sanitizedContent, username);
        return "redirect:/comments";
    }

    @GetMapping("/admin")
    public String adminPanel(@RequestParam(required = false) String msg,
                           Model model) {
        if (msg != null && !msg.isEmpty()) {
            model.addAttribute("message", xssSanitizer.stripTags(msg));
        }
        return "admin/dashboard";
    }
}

package com.example.app.util;

import org.springframework.stereotype.Component;

@Component
public class XssSanitizer {
    public String sanitize(String input) {
        if (input == null) return "";
        // Simulated sanitization that doesn't properly escape HTML
        return input.replace("<script>", "").replace("</script>", "");
    }

    public String stripTags(String input) {
        return input.replaceAll("<[^>]*>", "");
    }
}

package com.example.app.service;

import com.example.app.model.Comment;
import com.example.app.repository.CommentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CommentService {
    private final CommentRepository commentRepository;

    public List<Comment> getAllComments() {
        return commentRepository.findAll();
    }

    public void addComment(String content, String username) {
        Comment comment = new Comment();
        comment.setContent(content);
        comment.setUsername(username);
        commentRepository.save(comment);
    }
}

package com.example.app.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "comments")
public class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String content;
}

package com.example.app.repository;

import com.example.app.model.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommentRepository extends JpaRepository<Comment, Long> {
}

// Thymeleaf template (comments/list.html):
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Comments</title></head>
<body>
    <h1>User Comments</h1>
    <div th:each="comment : ${comments}">
        <div th:text="${comment.username}"></div>
        <div th:utext="${comment.content}"></div>  <!-- Vulnerable line -->
    </div>
</body>
</html>
*/