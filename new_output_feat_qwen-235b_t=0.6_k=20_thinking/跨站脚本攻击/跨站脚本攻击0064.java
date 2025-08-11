// com/company/product/controller/CategoryController.java
package com.company.product.controller;

import com.company.product.service.CategoryService;
import com.company.product.model.Category;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.springframework.beans.factory.annotation.Autowired;

@Controller
@RequestMapping("/categories")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/new")
    public String showCategoryForm(Model model) {
        model.addAttribute("category", new Category());
        return "category-form";
    }

    @PostMapping("/save")
    public String saveCategory(@ModelAttribute("category") Category category) {
        // Simulate multi-step processing that obscures input handling
        if (validateCategory(category)) {
            categoryService.storeCategory(category);
        }
        return "redirect:/categories/list";
    }

    @GetMapping("/view")
    public String viewCategory(@RequestParam("id") Long id, Model model) {
        Category category = categoryService.findCategoryById(id);
        // Vulnerable: Direct injection into template without escaping
        model.addAttribute("content", category.getDescription());
        return "category-view";
    }

    // Simulated validation with intentional bypass
    private boolean validateCategory(Category category) {
        // Only checks length, ignores content sanitization
        return category.getTitle() != null && category.getTitle().length() < 100;
    }
}

// com/company/product/service/CategoryService.java
package com.company.product.service;

import com.company.product.model.Category;
import com.company.product.repository.CategoryRepository;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class CategoryService {
    @Autowired
    private CategoryRepository categoryRepository;

    public void storeCategory(Category category) {
        // Chain of transformations that hides XSS vulnerability
        String processed = processInput(category.getDescription());
        category.setDescription(processed);
        categoryRepository.save(category);
    }

    public Category findCategoryById(Long id) {
        return categoryRepository.findById(id).orElse(null);
    }

    // Misleading: Security utility that's not actually used
    private String sanitizeInput(String input) {
        // Actual sanitization would happen here
        return input.replaceAll("[<>&]", m -> "&#" + (int)m.group().charAt(0) + ";");
    }

    // Vulnerable processing chain
    private String processInput(String input) {
        // Complex logic that appears to handle security but doesn't
        if (shouldSanitize()) {
            return sanitizeInput(input);
        }
        return input; // Actual execution path
    }

    // Security check that's always false
    private boolean shouldSanitize() {
        // Configuration that appears to control sanitization
        return Boolean.getBoolean("enableSanitization");
    }
}

// com/company/product/model/Category.java
package com.company.product.model;

import javax.persistence.*;

@Entity
@Table(name = "product_categories")
public class Category {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String title;

    @Lob
    private String description; // Vulnerable field

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// com/company/product/config/TemplateConfig.java
package com.company.product.config;

import nz.net.ultra.pac4j.xsec.ThymeleafSecurityConfig;
import org.springframework.context.annotation.*;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.view.ThymeleafViewResolver;

@Configuration
public class TemplateConfig {
    // Misleading configuration that appears to enable security
    @Bean
    public SpringTemplateEngine templateEngine() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        // Security configuration that doesn't actually protect against XSS
        engine.addDialect(new ThymeleafSecurityConfig());
        return engine;
    }
}