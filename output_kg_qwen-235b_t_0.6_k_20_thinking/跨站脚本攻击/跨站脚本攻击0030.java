package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }

    @Bean
    public CommentService commentService() {
        return new CommentService();
    }
}

@Controller
@RequestMapping("/comments")
class CommentController {
    private final CommentService commentService;

    public CommentController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping
    public @ResponseBody String getComments() {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>")
            .append("<h1>User Comments</h1>")
            .append("<div style='border:1px solid #ccc;padding:10px;'>");
        
        for (String comment : commentService.getComments()) {
            // 漏洞点：直接拼接用户输入到HTML响应
            html.append("<div style='margin:10px 0;padding:8px;background:#f5f5f5;'>")
                .append(comment)
                .append("</div>");
        }
        
        html.append("</div>")
            .append("<form method='post' style='margin-top:20px;'>")
            .append("<textarea name='content' style='width:100%;height:100px;'></textarea>")
            .append("<button type='submit'>Submit</button>")
            .append("</form>")
            .append("</body></html>");
            
        return html.toString();
    }

    @PostMapping
    public String addComment(@RequestParam String content) {
        commentService.addComment(content);
        return "redirect:/comments";
    }
}

class CommentService {
    private final List<String> comments = new ArrayList<>();

    public void addComment(String comment) {
        comments.add(comment);
    }

    public List<String> getComments() {
        return comments;
    }
}