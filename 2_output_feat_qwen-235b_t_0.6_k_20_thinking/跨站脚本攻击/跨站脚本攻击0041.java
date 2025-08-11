package com.example.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.example.app.service.CommentService;

/**
 * 用户评论控制器，处理评论提交与展示逻辑
 */
@Controller
public class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    /**
     * 展示评论提交表单
     */
    @GetMapping("/comment")
    public String showForm() {
        return "comment-form";
    }

    /**
     * 处理评论提交并重定向到展示页面
     */
    @PostMapping("/submit")
    public String submitComment(@RequestParam String content, Model model) {
        // 存储评论内容到模型用于视图渲染
        model.addAttribute("userComment", content);
        // 持久化存储评论数据
        commentService.storeComment(content);
        return "redirect:/comments";
    }

    /**
     * 展示所有用户评论
     */
    @GetMapping("/comments")
    public String showComments(Model model) {
        // 从存储服务获取所有评论数据
        model.addAttribute("comments", commentService.getAllComments());
        return "comment-list";
    }
}