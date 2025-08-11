package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@Entity
class Comment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String content;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

interface CommentRepository extends JpaRepository<Comment, Long> {}

@Service
class CommentService {
    private final CommentRepository repository;

    public CommentService(CommentRepository repository) {
        this.repository = repository;
    }

    public List<Comment> getAllComments() {
        return repository.findAll();
    }

    public void addComment(String content) {
        repository.save(new Comment() {{ setContent(content); }});
    }
}

@Controller
class CommentController {
    private final CommentService service;

    public CommentController(CommentService service) {
        this.service = service;
    }

    @GetMapping("/")
    public String showComments(Model model) {
        model.addAttribute("comments", service.getAllComments());
        return "comments";
    }

    @PostMapping("/add")
    public String addComment(@RequestParam String content) {
        service.addComment(content);
        return "redirect:/";
    }
}

// templates/comments.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h1>Comments</h1>
//     <div th:each="comment : ${comments}">
//         <div th:utext="${comment.content}"></div>  <!-- Vulnerable line -->
//     </div>
//     <form action="/add" method="post">
//         <textarea name="content"></textarea>
//         <button type="submit">Submit</button>
//     </form>
// </body>
// </html>