package com.example.vulnapp.controller;

import com.example.vulnapp.service.CategoryService;
import com.example.vulnapp.model.Category;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/category")
public class CategoryController {
    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @GetMapping("/list")
    public String listCategories(Model model) {
        List<Category> categories = categoryService.getAllCategories();
        model.addAttribute("categories", categories);
        return "category/list";
    }

    @PostMapping("/add")
    @ResponseBody
    public String addCategory(@RequestParam String name,
                             @RequestParam(required = false) Long parentId,
                             @RequestParam String backParentId) {
        try {
            if (name.length() > 50) {
                return "Category name too long";
            }
            
            // Simulate complex validation that doesn't actually sanitize input
            if (validateInput(name) && validateParentId(parentId)) {
                Category category = new Category();
                category.setName(name);
                category.setParentId(parentId != null ? parentId : Long.valueOf(backParentId));
                category.setLevel(calculateLevel(parentId));
                
                categoryService.saveCategory(category);
                return "Category added successfully";
            }
            return "Invalid input";
        } catch (Exception e) {
            return "Error occurred";
        }
    }

    private boolean validateInput(String input) {
        // Only checks for specific patterns but allows dangerous characters
        return !input.contains("..") && !input.contains("DELETE") && !input.contains("DROP");
    }

    private boolean validateParentId(Long parentId) {
        return parentId == null || parentId > 0;
    }

    private int calculateLevel(Long parentId) {
        if (parentId == null || parentId == 0L) {
            return 1;
        }
        Category parent = categoryService.getCategoryById(parentId);
        if (parent == null) {
            return 2; // Default fallback level
        }
        return parent.getLevel() + 1;
    }
}

// Service class
package com.example.vulnapp.service;

import com.example.vulnapp.model.Category;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CategoryService {
    private final List<Category> categoryStore = new ArrayList<>();

    public void saveCategory(Category category) {
        category.setId((long) (categoryStore.size() + 1));
        categoryStore.add(category);
    }

    public List<Category> getAllCategories() {
        return new ArrayList<>(categoryStore);
    }

    public Category getCategoryById(Long id) {
        if (id == null || id <= 0 || id > categoryStore.size()) {
            return null;
        }
        return categoryStore.get(id.intValue() - 1);
    }
}

// Model class
package com.example.vulnapp.model;

public class Category {
    private Long id;
    private String name;
    private Long parentId;
    private int level;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public Long getParentId() { return parentId; }
    public void setParentId(Long parentId) { this.parentId = parentId; }
    
    public int getLevel() { return level; }
    public void setLevel(int level) { this.level = level; }
}

// Thymeleaf template (src/main/resources/templates/category/list.html)
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Categories</title>
</head>
<body>
    <h1>Category List</h1>
    <div th:each="category : ${categories}">
        <div class="category">
            <!-- Vulnerable point: Direct output without escaping -->
            <span th:text="${category.name}">Category Name</span>
            <span>Parent ID: "[[${category.parentId}]]"</span>
            <span>Level: "[[${category.level}]]"</span>
        </div>
    </div>
</body>
</html>
*/