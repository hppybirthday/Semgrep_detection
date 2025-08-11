package com.example.xss.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@Controller
class CommentController {
    private final List<Comment> comments = new ArrayList<>();

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("comments", comments);
        return "index";
    }

    @PostMapping("/comment")
    public String addComment(@RequestParam String content, @RequestParam String author) {
        comments.add(new Comment(content, author));
        return "redirect:/";
    }
}

record Comment(String content, String author) {}
