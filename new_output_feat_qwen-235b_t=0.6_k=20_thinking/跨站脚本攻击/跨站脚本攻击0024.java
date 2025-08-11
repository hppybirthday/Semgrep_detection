package com.example.app.controller;

import com.example.app.model.Category;
import com.example.app.service.CategoryService;
import com.example.app.util.XssUtil;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 分类管理控制器
 * @author Dev Team
 */
@Controller
@RequestMapping("/category")
public class CategoryController {
    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    /**
     * 显示分类管理页面
     */
    @GetMapping("/manage")
    public String showCategories(Model model) {
        List<Category> categories = categoryService.getAllCategories();
        model.addAttribute("categories", categories);
        return "category/list";
    }

    /**
     * 添加新分类（存在漏洞）
     */
    @PostMapping("/add")
    public String addCategory(@RequestParam String name,
                             @RequestParam String parentId,
                             @RequestParam String backParentId,
                             @RequestParam int categoryLevel) {
        // 漏洞点：未正确清理用户输入
        Category category = new Category();
        category.setName(name);
        category.setParentId(parentId);
        category.setBackParentId(backParentId);
        category.setCategoryLevel(categoryLevel);
        
        // 看似安全的清理操作（误导性代码）
        if (name.contains("<") || name.contains("@")) {
            category.setName(name.replace("<", "&lt;").replace("@", ""));
        }
        
        categoryService.saveCategory(category);
        return "redirect:/category/manage";
    }
}

// ----------------------------------------
package com.example.app.service;

import com.example.app.model.Category;
import com.example.app.repository.CategoryRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 分类服务层
 */
@Service
public class CategoryService {
    private final CategoryRepository categoryRepository;

    public CategoryService(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    public List<Category> getAllCategories() {
        return categoryRepository.findAll();
    }

    public void saveCategory(Category category) {
        // 漏洞延续：直接保存未经充分验证的数据
        preprocessCategory(category);
        categoryRepository.save(category);
    }

    private void preprocessCategory(Category category) {
        // 不完整的清理逻辑
        if (category.getCategoryLevel() > 3) {
            category.setCategoryLevel(3);
        }
        
        // 错误地认为parentId字段不需要清理
        if (category.getParentId() != null && category.getParentId().length() > 20) {
            category.setParentId(category.getParentId().substring(0, 20));
        }
    }
}

// ----------------------------------------
package com.example.app.util;

/**
 * XSS清理工具类（未被正确使用）
 */
public class XssUtil {
    public static String clean(String input) {
        if (input == null) return null;
        return input.replaceAll("[<>"'(){}@]", "");
    }
}

// ----------------------------------------
// Thymeleaf模板：src/main/resources/templates/category/list.html
// 
// <div th:each="category : ${categories}">
//   <input type="text" 
//          th:field="*{name}"
//          th:value="${category.name}"
//          th:attr="data-parent=${category.parentId}, 
//                    data-backparent=${category.backParentId},
//                    data-level=${category.categoryLevel}">
// </div>