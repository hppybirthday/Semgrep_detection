package com.example.xss.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class CommentController {
    @Autowired
    private CommentService commentService;

    @PostMapping("/comments")
    public ResponseEntity<Void> createComment(@RequestBody Comment comment) {
        if (comment == null || comment.getId() == null || comment.getContent() == null) {
            return ResponseEntity.badRequest().build();
        }
        commentService.addComment(comment);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/comment")
    public ResponseEntity<String> displayComment(@RequestParam String id) {
        Comment comment = commentService.getComment(id);
        if (comment == null) {
            return ResponseEntity.notFound().build();
        }
        String htmlResponse = "<html><body><h1>Comment:</h1><div>" + comment.getContent() + "</div></body></html>";
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(htmlResponse);
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("OK");
    }
}

class CommentService {
    private Map<String, Comment> comments = new HashMap<>();

    void addComment(Comment comment) {
        comments.put(comment.getId(), comment);
    }

    Comment getComment(String id) {
        return comments.get(id);
    }
}

class Comment {
    private String id;
    private String content;

    public Comment() {}

    public Comment(String id, String content) {
        this.id = id;
        this.content = content;
    }

    String getId() { return id; }
    void setId(String id) { this.id = id; }
    String getContent() { return content; }
    void setContent(String content) { this.content = content; }
}