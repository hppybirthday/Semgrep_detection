package com.example.mathmodelling;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class MathModellingApp {
    public static void main(String[] args) {
        SpringApplication.run(MathModellingApp.class, args);
    }
}

@Entity
class MathematicalModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String description;
    // 漏洞点：未对用户输入进行过滤或转义

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

interface ModelRepository extends JpaRepository<MathematicalModel, Long> {}

@Controller
@RequestMapping("/models")
class ModelController {
    private final ModelRepository repository;

    public ModelController(ModelRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public String listModels(Model model) {
        List<MathematicalModel> models = repository.findAll();
        model.addAttribute("models", models);
        return "model-list"; // Thymeleaf模板直接渲染未经转义的内容
    }

    @PostMapping
    public String createModel(@RequestParam String name, @RequestParam String description) {
        // 漏洞点：直接保存未经验证的用户输入
        MathematicalModel model = new MathematicalModel();
        model.setName(name);
        model.setDescription(description);
        repository.save(model);
        return "redirect:/models";
    }
}

// Thymeleaf模板(model-list.html):
// <div th:each="model : ${models}">
//   <h3 th:text="${model.name}"></h3> <!-- 漏洞点：直接渲染未经转义的内容 -->
//   <p th:text="${model.description}"></p>
// </div>
// 
// 恶意输入示例：
// <script>alert(document.cookie)</script>
// 或
// <img src="x" onerror="alert('xss')">