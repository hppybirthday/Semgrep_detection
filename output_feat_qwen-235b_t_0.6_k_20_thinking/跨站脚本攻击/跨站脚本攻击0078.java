package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@Entity
class Post {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title; // Vulnerable: Raw user input storage

    // Getters/Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
}

interface PostRepository extends JpaRepository<Post, Long> {
    List<Post> findByTitleContaining(String keyword);
}

@Controller
class PostController {
    private final PostRepository postRepo;

    public PostController(PostRepository postRepo) {
        this.postRepo = postRepo;
    }

    @GetMapping("/create")
    String createForm() {
        return "create";
    }

    @PostMapping("/create")
    String createPost(@RequestParam String title) {
        postRepo.save(new Post() {{
            setTitle(title); // Vulnerable: No input sanitization
        }});
        return "redirect:/posts";
    }

    @GetMapping("/posts")
    String listPosts(Model model) {
        model.addAttribute("posts", postRepo.findAll());
        return "posts";
    }
}

// Thymeleaf template (resources/templates/posts.html):
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <h1>Posts</h1>
//   <div th:each="post : ${posts}">
//     <script th:inline="javascript">
//       /*<![CDATA[*/
//       var postTitle = /*[(${__${post.title}__})]*/ ''; // Vulnerable: Raw output in JS context
//       console.log('Post title: ' + postTitle);
//       /*]]>*/
//     </script>
//   </div>
// </body>
// </html>