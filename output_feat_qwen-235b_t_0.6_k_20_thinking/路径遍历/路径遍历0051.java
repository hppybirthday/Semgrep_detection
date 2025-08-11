package com.example.taskmanager;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/categories")
public class CategoryController {
    private final CategoryService categoryService = new CategoryService();

    @PutMapping("/{id}")
    public String updateCategory(@PathVariable Long id, @RequestParam String bizType, @RequestBody CategoryDTO dto) {
        try {
            categoryService.updateCategory(id, bizType, dto);
            return "Category updated successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class CategoryDTO {
    private String name;
    // getters and setters
}

class Category {
    private Long id;
    private String name;
    private String path;
    // getters and setters
}

class CategoryService {
    private final Path basePath = Paths.get("assets/");

    public void updateCategory(Long id, String bizType, CategoryDTO dto) throws Exception {
        // Simulate database lookup
        Category category = new Category();
        category.setId(id);
        category.setName(dto.getName());
        
        // Vulnerable path construction
        Path targetPath = basePath.resolve(bizType).normalize();
        
        // Simulate file operation
        if (Files.exists(targetPath)) {
            byte[] content = Files.readAllBytes(targetPath);
            System.out.println("Read content size: " + content.length);
        }
        
        // Simulate persistent storage
        Path savePath = basePath.resolve(category.getName() + ".data");
        Files.write(savePath, dto.getName().getBytes());
        
        // Vulnerable operation: Path traversal in bizType parameter
        System.out.println("Processed path: " + targetPath.toString());
    }
}