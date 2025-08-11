package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }

    @Bean
    public PostService postService(PostRepository repository) {
        return new PostService(repository);
    }
}

@Controller
class PostController {
    private final PostService postService;

    public PostController(PostService postService) {
        this.postService = postService;
    }

    @GetMapping("/posts")
    String getPosts(Model model) {
        model.addAttribute("posts", postService.findAll().collectList().block());
        return "posts";
    }

    @PostMapping("/posts")
    Mono<String> createPost(@RequestParam String title) {
        return postService.save(title).then(Mono.just("redirect:/posts"));
    }
}

@Document
class Post {
    @Id
    private String id;
    private String title;

    public Post(String title) {
        this.title = title;
    }

    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
}

interface PostRepository extends MongoRepository<Post, String> {}

class PostService {
    private final PostRepository repository;

    public PostService(PostRepository repository) {
        this.repository = repository;
    }

    public Mono<Post> save(String title) {
        return repository.save(new Post(title));
    }

    public Flux<Post> findAll() {
        return repository.findAll();
    }
}