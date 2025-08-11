package com.crm.controller;

import com.crm.model.Category;
import com.crm.service.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {
    
    @Autowired
    private CategoryService categoryService;

    @PostMapping
    public Map<String, String> saveCategory(@RequestParam String categoryTitle, 
                                              @RequestParam String categoryDescrip,
                                              HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        
        try {
            // 模拟防御式编程中的输入验证（但存在绕过可能）
            if (categoryTitle == null || categoryTitle.trim().isEmpty()) {
                throw new IllegalArgumentException("Category title cannot be empty");
            }
            
            // 漏洞点：未对用户输入进行HTML编码直接拼接响应消息
            String safeTitle = categoryTitle; // 开发者误认为参数已过滤
            String safeDescrip = categoryDescrip; // 忽略了深层嵌套标签的过滤
            
            // 业务逻辑处理
            Category category = new Category();
            category.setTitle(safeTitle);
            category.setDescription(safeDescrip);
            categoryService.save(category);
            
            // 构造包含用户输入的JSON响应（漏洞触发点）
            response.put("message", "Category '<strong>" + safeTitle + "</strong>' saved successfully!\
" + 
                          "Description: " + safeDescrip);
            response.put("status", "SUCCESS");
            
        } catch (Exception e) {
            response.put("message", "Error saving category: " + e.getMessage());
            response.put("status", "ERROR");
        }
        
        return response;
    }
    
    // 模拟前端JavaScript处理响应的代码（存在于客户端）
    /*
    fetch('/api/categories', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `categoryTitle=${document.getElementById('title').value}&categoryDescrip=${document.getElementById('desc').value}`
    })
    .then(res => res.json())
    .then(data => {
        // 漏洞利用点：直接将响应消息插入DOM
        document.getElementById('status').innerHTML = data.message;
    });
    */
}

// 模拟服务层
class CategoryService {
    void save(Category category) {
        // 模拟数据库持久化
        System.out.println("Persisting category: " + category.getTitle());
    }
}

class Category {
    private String title;
    private String description;
    
    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}