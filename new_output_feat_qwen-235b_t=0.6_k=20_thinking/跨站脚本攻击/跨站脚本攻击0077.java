package com.chat.app.controller;

import com.chat.app.model.Category;
import com.chat.app.service.CategoryService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/categories")
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

    @PostMapping("/save")
    public String saveCategory(@RequestParam String name,
                               @RequestParam(required = false) String parentId,
                               @RequestParam(required = false) String backParentId) {
        Category category = new Category();
        category.setName(sanitizeInput(name));
        
        if (parentId != null && parentId.matches("\\d+")) {
            category.setParentId(parentId);
        }
        
        // Vulnerable code: backParentId is stored without sanitization
        category.setBackParentId(backParentId != null ? backParentId : "0");
        
        categoryService.saveCategory(category);
        return "redirect:/categories/list";
    }

    @GetMapping("/jsonp")
    @ResponseBody
    public String jsonpCallback(@RequestParam String callback,
                                @RequestParam String filter) {
        List<Category> categories = categoryService.findCategoriesByFilter(filter);
        StringBuilder result = new StringBuilder(callback).append("({\\"data\\":[");
        
        for (int i = 0; i < categories.size(); i++) {
            if (i > 0) result.append(",");
            result.append("{\\"name\\":\\"").append(categories.get(i).getName()).append("\\"}");
        }
        
        result.append("]})");
        return result.toString();
    }

    // Security bypass: This method is ineffective against XSS payloads
    private String sanitizeInput(String input) {
        if (input == null) return null;
        return input.replaceAll("[<>]", "");
    }
}

// Thymeleaf template (resources/templates/category/list.html)
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Categories</title></head>
<body>
    <h1>Category List</h1>
    <div th:each="category : ${categories}">
        <div>
            <!-- Vulnerable context: HTML text context injection -->
            <span th:text="${category.name}"></span>
            <!-- Hidden vulnerability: backParentId used in data attribute -->
            <div th:attr="data-parent=${category.backParentId}"></div>
        </div>
    </div>
    
    <!-- Safe context: Properly escaped input -->
    <div th:text="*{#strings.escapeXml(category.name)}"></div>
</body>
</html>
*/