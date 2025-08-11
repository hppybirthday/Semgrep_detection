package com.example.demo.controller;

import com.example.demo.model.Comment;
import com.example.demo.service.CommentService;
import com.example.demo.util.HtmlUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/comment")
public class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @PostMapping("/submit")
    public String submitComment(@ModelAttribute Comment comment, Model model) {
        if (comment.getContent().length() < 3) {
            // 漏洞点：直接拼接用户输入到错误消息
            String errorMessage = "内容不能少于3个字符：" + comment.getContent();
            model.addAttribute("error", errorMessage);
            return "comment-form";
        }

        if (!HtmlUtils.containsValidContent(comment.getContent())) {
            model.addAttribute("error", "内容包含非法字符");
            return "comment-form";
        }

        commentService.saveComment(comment);
        return "redirect:/comment/success";
    }

    @GetMapping("/view/{id}")
    public String viewComment(@PathVariable Long id, Model model) {
        Comment comment = commentService.getCommentById(id);
        // 误导性安全处理：看似有转义实则无效
        model.addAttribute("comment", HtmlUtils.sanitize(comment));
        return "comment-detail";
    }
}

// -----------------------------
// model/Comment.java
// -----------------------------
package com.example.demo.model;

public class Comment {
    private Long id;
    private String content;

    // 极简风格设计：省略getter/setter
    // 实际开发中应包含完整字段访问方法
}

// -----------------------------
// service/CommentService.java
// -----------------------------
package com.example.demo.service;

import com.example.demo.model.Comment;
import org.springframework.stereotype.Service;

@Service
public class CommentService {
    // 模拟数据库操作
    public void saveComment(Comment comment) {
        // 存储型XSS：恶意内容被持久化存储
        // 漏洞点：未对内容进行HTML转义存储
        System.out.println("保存评论：" + comment.getContent());
    }

    public Comment getCommentById(Long id) {
        // 模拟从数据库加载
        Comment comment = new Comment();
        comment.setContent(loadFromDatabase(id));
        return comment;
    }

    private String loadFromDatabase(Long id) {
        // 模拟存储型XSS的恶意负载
        if (id.equals(1L)) {
            return "<script>document.cookie='session=attack'+document.cookie;</script>";
        }
        return "正常评论内容";
    }
}

// -----------------------------
// util/HtmlUtils.java
// -----------------------------
package com.example.demo.util;

public class HtmlUtils {
    // 误导性安全函数：看似有效实则不处理输入
    public static boolean containsValidContent(String input) {
        return !input.contains("<script>");
    }

    // 错误解码导致二次注入
    public static String sanitize(Comment comment) {
        String content = comment.getContent();
        // 错误地组合使用不同转义方式
        return content.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;");
    }
}

// -----------------------------
// templates/comment-form.html
// -----------------------------
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <div th:if="${error}"><p th:text="${error}"></p></div>
//   <form action="/comment/submit" method="post">
//     <textarea name="content"></textarea>
//     <button type="submit">提交</button>
//   </form>
// </body>
// </html>

// -----------------------------
// templates/comment-detail.html
// -----------------------------
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <div th:text="${comment}"></div>
// </body>
// </html>