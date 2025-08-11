package com.example.xss.demo.domain.comment;

import java.util.Objects;

public class Comment {
    private String id;
    private String content;

    public Comment(String id, String content) {
        this.id = id;
        this.content = content;
    }

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

// Repository
package com.example.xss.demo.infrastructure.persistence;

import com.example.xss.demo.domain.comment.Comment;
import java.util.HashMap;
import java.util.Map;

public class CommentRepository {
    private final Map<String, Comment> database = new HashMap<>();

    public void save(Comment comment) {
        database.put(comment.getId(), comment);
    }

    public Comment findById(String id) {
        return database.get(id);
    }
}

// Service
package com.example.xss.demo.application.services;

import com.example.xss.demo.domain.comment.Comment;
import com.example.xss.demo.infrastructure.persistence.CommentRepository;

public class CommentService {
    private final CommentRepository repository;

    public CommentService(CommentRepository repository) {
        this.repository = repository;
    }

    public void postComment(Comment comment) {
        // Vulnerability: No input validation/cleaning
        repository.save(comment);
    }

    public Comment getComment(String id) {
        return repository.findById(id);
    }
}

// Controller
package com.example.xss.demo.interfaces.rest;

import com.example.xss.demo.application.services.CommentService;
import com.example.xss.demo.domain.comment.Comment;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/comments")
public class CommentController {
    private final CommentService service;

    public CommentController(CommentService service) {
        this.service = service;
    }

    @PostMapping
    public void createComment(@RequestBody Comment comment) {
        service.postComment(comment);
    }

    @GetMapping("/{id}")
    public Comment getComment(@PathVariable String id) {
        return service.getComment(id);
    }
}

// Configuration
package com.example.xss.demo;

import com.example.xss.demo.application.services.CommentService;
import com.example.xss.demo.infrastructure.persistence.CommentRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    @Bean
    public CommentRepository commentRepository() {
        return new CommentRepository();
    }

    @Bean
    public CommentService commentService(CommentRepository repository) {
        return new CommentService(repository);
    }
}