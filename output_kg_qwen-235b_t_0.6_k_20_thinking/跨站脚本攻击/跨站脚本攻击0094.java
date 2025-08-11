package com.example.xssdemo;

import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/comments")
public class CommentController {
    private Map<Long, String> comments = new HashMap<>();
    private Long idCounter = 0L;

    @PostMapping
    public ResponseEntity<Long> addComment(@RequestParam String content) {
        Long id = ++idCounter;
        comments.put(id, content);
        return ResponseEntity.ok(id);
    }

    @GetMapping("/{id}")
    public String getComment(@PathVariable Long id) {
        String content = comments.getOrDefault(id, "Not found");
        return "<html><body><div>" + content + "</div></body></html>";
    }

    @GetMapping("/search")
    public String searchComments(@RequestParam String query) {
        StringBuilder result = new StringBuilder("<ul>");
        comments.forEach((id, text) -> {
            if (text.contains(query)) {
                result.append("<li><a href='/comments/").append(id)
                    .append("'>").append(text).append("</a></li>");
            }
        });
        result.append("</ul>");
        return result.toString();
    }

    @PostMapping("/update")
    public ResponseEntity<String> updateComment(@RequestParam Long id, @RequestParam String newContent) {
        if (comments.containsKey(id)) {
            comments.put(id, newContent);
            return ResponseEntity.ok("Updated");
        }
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/list")
    public String listAllComments() {
        StringBuilder html = new StringBuilder("<ul>");
        comments.forEach((id, text) -> {
            html.append("<li>")
                .append("<strong>ID: ").append(id).append("</strong>")
                .append("<p>").append(text).append("</p>")
                .append("</li>");
        });
        html.append("</ul>");
        return html.toString();
    }
}

// 模拟实体类
class Comment {
    private Long id;
    private String content;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}