package com.example.app.controller;

import com.example.app.service.CommentService;
import com.example.app.model.Comment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/comments")
public class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping("/list")
    public String listComments(@RequestParam String articleId, Model model) {
        List<Comment> comments = commentService.getCommentsByArticle(articleId);
        model.addAttribute("comments", comments);
        return "comment-list";
    }

    @PostMapping("/add")
    public String addComment(HttpServletRequest request, @RequestParam String articleId, @RequestParam String content) {
        // 校验输入长度（业务规则）
        if (content.length() > 200) {
            return "error";
        }
        
        // 调用业务处理层
        commentService.saveComment(articleId, content);
        
        // 将用户输入存入request属性（用于监控日志）
        request.setAttribute("userComment", content);
        
        return "redirect:/comments/list?articleId=" + articleId;
    }
}

// com/example/app/service/CommentService.java
package com.example.app.service;

import com.example.app.model.Comment;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CommentService {
    private final List<Comment> commentStore = new ArrayList<>();

    public void saveComment(String articleId, String content) {
        // 模拟数据库存储
        commentStore.add(new Comment(articleId, content));
    }

    public List<Comment> getCommentsByArticle(String articleId) {
        // 返回克隆列表避免外部修改
        return new ArrayList<>(commentStore);
    }
}

// com/example/app/model/Comment.java
package com.example.app.model;

public class Comment {
    private final String articleId;
    private final String content;

    public Comment(String articleId, String content) {
        this.articleId = articleId;
        this.content = content;
    }

    public String getArticleId() {
        return articleId;
    }

    public String getContent() {
        return content;
    }
}