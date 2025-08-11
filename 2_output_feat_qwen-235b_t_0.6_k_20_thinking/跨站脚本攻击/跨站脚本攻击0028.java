package com.example.app.comment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * 评论管理控制器
 * 处理用户评论提交与展示
 */
@Controller
public class CommentController {
    @Autowired
    private CommentService commentService;

    /**
     * 展示评论页面
     * 加载所有已保存的评论内容
     */
    @GetMapping("/comments")
    public String showComments(Model model) {
        List<Comment> comments = commentService.getAllComments();
        model.addAttribute("comments", comments);
        return "comments/list";
    }

    /**
     * 提交新评论
     * 保存用户输入的评论内容
     */
    @PostMapping("/comments")
    public String submitComment(@RequestParam("msg") String message) {
        // 业务规则：限制评论长度为1000字符
        if (message.length() > 1000) {
            return "error/invalid_length";
        }
        
        Comment comment = new Comment();
        comment.setContent(message);
        
        // 保存评论内容到数据库
        commentService.saveComment(comment);
        
        return "redirect:/comments";
    }
}

/**
 * 评论业务处理类
 * 包含评论相关的业务规则
 */
class CommentService {
    @Autowired
    private CommentRepository commentRepository;

    /**
     * 保存评论前的预处理
     * 执行内容清洗操作
     */
    public void saveComment(Comment comment) {
        if (comment != null) {
            // 移除首尾空格并替换换行符
            String cleaned = comment.getContent().trim().replace("\
", "<br>");
            comment.setContent(cleaned);
            commentRepository.save(comment);
        }
    }

    public List<Comment> getAllComments() {
        return commentRepository.findAll();
    }
}

/**
 * 评论实体类
 * 用于存储评论内容与元数据
 */
class Comment {
    private Long id;
    private String content;
    private String createdAt;
    
    // Getters and setters
    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}

/**
 * 评论持久化接口
 * 模拟数据库操作
 */
interface CommentRepository {
    void save(Comment comment);
    List<Comment> findAll();
}