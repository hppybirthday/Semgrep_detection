package com.example.xssdemo.comment;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class CommentService {
    private final List<Comment> comments = new ArrayList<>();

    public void addComment(String content) {
        comments.add(new Comment(content));
    }

    public List<Comment> getAllComments() {
        return new ArrayList<>(comments);
    }
}

package com.example.xssdemo.comment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/comments")
public class CommentController {
    @Autowired
    private CommentService commentService;

    @PostMapping
    public String addComment(@RequestParam String content) {
        commentService.addComment(content);
        return "Redirecting to comments page";
    }

    @GetMapping
    public String listComments() {
        StringBuilder html = new StringBuilder("<html><body><h1>Comments:</h1>");
        for (Comment comment : commentService.getAllComments()) {
            // Vulnerable code: Directly inserting user input into HTML without sanitization
            html.append("<div class='comment'>").append(comment.getContent()).append("</div>");
        }
        html.append("<form method='post' action='/comments'>")
           .append("<textarea name='content'></textarea>")
           .append("<button type='submit'>Submit</button>")
           .append("</form></body></html>");
        return html.toString();
    }
}

package com.example.xssdemo.comment;

public class Comment {
    private final String content;

    public Comment(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }
}

// Application.java (Main class)
package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}