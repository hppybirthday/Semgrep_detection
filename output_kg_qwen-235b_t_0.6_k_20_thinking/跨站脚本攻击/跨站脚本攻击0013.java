package com.example.xssdemo;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class CommentService {
    private List<Comment> comments = new ArrayList<>();

    public void saveComment(String content) {
        // 错误防御：仅移除<script>标签但保留属性
        String sanitized = content.replaceAll("<(?i)script.*?>.*?</(?i)script>", "");
        comments.add(new Comment(sanitized));
    }

    public List<Comment> getAllComments() {
        return new ArrayList<>(comments);
    }
}

package com.example.xssdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@RestController
public class CommentController {
    @Autowired
    private CommentService commentService;

    @GetMapping("/comments")
    public ModelAndView showComments() {
        ModelAndView mav = new ModelAndView("comments");
        mav.addObject("comments", commentService.getAllComments());
        return mav;
    }

    @PostMapping("/add")
    public String addComment(@RequestParam String content) {
        commentService.saveComment(content);
        return "redirect:/comments";
    }
}

package com.example.xssdemo;

public class Comment {
    private String content;

    public Comment(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

// Thymeleaf模板（resources/templates/comments.html）
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>XSS Demo</title></head>
// <body>
// <div th:each="comment : ${comments}">
//     <p th:utext="${comment.content}"></p>  // 使用不安全的utext
// </div>
// <form action="/add" method="post">
//     <textarea name="content"></textarea>
//     <button>Submit</button>
// </form>
// </body>
// </html>