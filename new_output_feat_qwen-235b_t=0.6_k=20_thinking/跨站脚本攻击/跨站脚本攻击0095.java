package com.example.app.comment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CommentService {
    private final CommentRepository commentRepository;

    @Autowired
    public CommentService(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    public void storeComment(String rawComment) {
        String sanitized = sanitizeComment(rawComment);
        commentRepository.save(new Comment(sanitized));
    }

    // 漏洞点：不完整的输入清理逻辑
    private String sanitizeComment(String input) {
        if (input == null) return "";
        
        // 错误地认为过滤script标签即可
        String result = input.replace("<script>", "").replace("</script>", "");
        
        // 潜在危险的编码转换
        return result.replaceAll("(\\W|^)on\\w+", "_removed_");
    }

    public Iterable<Comment> getAllComments() {
        return commentRepository.findAll();
    }
}

package com.example.app.comment;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/comments")
public class CommentController {
    private final CommentService commentService;

    @Autowired
    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @PostMapping
    public void addComment(@RequestParam String content) {
        commentService.storeComment(content);
    }
}

package com.example.app.comment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CommentViewController {
    private final CommentService commentService;

    @Autowired
    public CommentViewController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping("/comments")
    public String showComments(Model model) {
        model.addAttribute("comments", commentService.getAllComments());
        return "comment-list";
    }
}

// Thymeleaf模板：resources/templates/comment-list.html
// 漏洞点：在HTML属性上下文中使用不安全的数据绑定
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>用户评论</title>
</head>
<body>
    <h1>用户评论列表</h1>
    <div th:each="comment : ${comments}">
        <!-- 漏洞点：未正确转义HTML属性值 -->
        <input type="text" value="[[${comment.commentText}]]" 
               onfocus="this.select()"/>
    </div>
</body>
</html>
*/