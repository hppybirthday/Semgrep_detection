package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.persistence.*;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
public class XssVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }
}

// == DOMAIN MODEL ==
@Entity
class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String content;
    private String author;
    
    public Comment() {}
    
    public Comment(String content, String author) {
        this.content = content;
        this.author = author;
    }

    public Long getId() { return id; }
    public String getContent() { return content; }
    public String getAuthor() { return author; }
}

// == REPOSITORY ==
interface CommentRepository extends JpaRepository<Comment, Long> {}

// == SERVICE LAYER ==
@Service
class CommentService {
    @Autowired
    private CommentRepository repository;
    
    public List<Comment> getAllComments() {
        return repository.findAll();
    }
    
    public void saveComment(Comment comment) {
        repository.save(comment);
    }
}

// == VIEW RENDERER ==
@Component
class CommentRenderer {
    public String renderComment(Comment comment) {
        // 模拟HTML模板渲染引擎
        return "<div class='comment'>" + 
               "<div class='author'>" + comment.getAuthor() + "</div>" +
               "<div class='content'>" + comment.getContent() + "</div>" +
               "</div>";
    }
    
    // 模拟不完整的安全处理
    public String safeEncode(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// == CONTROLLER ==
@RestController
class CommentController {
    @Autowired
    private CommentService service;
    
    @Autowired
    private CommentRenderer renderer;
    
    @Autowired
    private TemplateEngine templateEngine;
    
    // 提交评论接口
    @PostMapping("/comments")
    public String submitComment(@RequestParam String content, 
                              @RequestParam String author) {
        Comment comment = new Comment(processContent(content), author);
        service.saveComment(comment);
        return "redirect:/comments";
    }
    
    // 展示评论页面
    @GetMapping("/comments")
    public String listComments(Model model) {
        List<Comment> comments = service.getAllComments();
        List<String> rendered = comments.stream()
            .map(renderer::renderComment)
            .collect(Collectors.toList());
            
        // 模拟动态模板渲染
        Context context = new Context();
        context.setVariable("comments", rendered);
        return templateEngine.process("comments", context);
    }
    
    // 模拟不完整的输入处理
    private String processContent(String content) {
        // 错误的编码处理：只替换基本标签
        return content.replace("<script>", "&lt;script&gt;")
                     .replace("</script>", "&lt;/script&gt;");
    }
}

// == MVC CONFIG ==
@Component
class WebConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/submit").setViewName("submit_form");
    }
}