package com.example.app.controller;

import com.example.app.service.CommentService;
import com.example.app.model.Comment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 用户评论管理控制器
 * 处理评论提交与展示功能
 */
@Controller
@RequestMapping("/comments")
public class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    /**
     * 提交新评论
     * @param request HTTP请求
     * @param commentContent 评论内容
     * @return 重定向到评论列表
     */
    @PostMapping
    public String submitComment(HttpServletRequest request, 
                               @RequestParam("content") String commentContent) {
        // 获取当前用户名
        String username = request.getRemoteUser();
        
        // 创建评论对象并设置属性
        Comment comment = new Comment();
        comment.setUsername(username);
        comment.setContent(commentContent.trim());
        
        // 存储评论到数据库
        commentService.saveComment(comment);
        
        return "redirect:/comments/list";
    }

    /**
     * 展示所有评论
     * @param model 数据模型
     * @return 评论列表视图
     */
    @GetMapping("/list")
    public String listComments(Model model) {
        // 获取所有已存储的评论
        List<Comment> comments = commentService.getAllComments();
        
        // 将评论列表添加到模型中
        model.addAttribute("comments", comments);
        
        return "comment/list";
    }
}

// ---------------------------------------
// com/example/app/service/CommentService.java
// ---------------------------------------
package com.example.app.service;

import com.example.app.model.Comment;
import com.example.app.repository.CommentRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 评论业务处理类
 * 提供评论的持久化与查询功能
 */
@Service
public class CommentService {
    private final CommentRepository commentRepository;

    public CommentService(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    /**
     * 保存评论到数据库
     * @param comment 评论实体
     */
    public void saveComment(Comment comment) {
        // 调用存储过程进行持久化
        commentRepository.save(comment);
    }

    /**
     * 获取所有评论
     * @return 评论列表
     */
    public List<Comment> getAllComments() {
        return commentRepository.findAll();
    }
}

// ---------------------------------------
// com/example/app/model/Comment.java
// ---------------------------------------
package com.example.app.model;

import lombok.Data;

/**
 * 评论数据模型
 * 包含用户标识与评论内容
 */
@Data
public class Comment {
    private Long id;
    private String username;
    private String content;
}

// ---------------------------------------
// Thymeleaf模板：resources/templates/comment/list.html
// ---------------------------------------
<!-- 评论展示模板 -->
<div class="comment-section">
    <div th:each="comment : ${comments}">
        <div class="username" th:text="${comment.username}"></div>
        <!-- 评论内容未进行HTML转义 -->
        <div class="content" th:utext="${comment.content}"></div>
    </div>
</div>