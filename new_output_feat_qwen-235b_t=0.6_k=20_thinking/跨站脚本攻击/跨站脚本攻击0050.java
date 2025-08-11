package com.smartiot.device.controller;

import com.smartiot.device.service.CategoryService;
import com.smartiot.device.model.DeviceCategory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.List;

/**
 * IoT设备分类管理控制器
 * @author IoT Security Team
 */
@Controller
@RequestMapping("/categories")
public class CategoryController {
    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    /**
     * 显示分类管理页面
     * @param model 视图模型
     * @return 页面名称
     */
    @GetMapping
    public String showCategories(Model model) {
        List<DeviceCategory> categories = categoryService.getAllCategories();
        model.addAttribute("categories", categories);
        return "categories/manage";
    }

    /**
     * 处理分类创建请求
     * @param category 设备分类实体
     * @return 重定向地址
     */
    @PostMapping
    public String createCategory(@ModelAttribute("category") DeviceCategory category) {
        // 漏洞点：看似安全的输入处理
        String safeTitle = sanitizeInput(category.getTitle());
        String safeDesc = sanitizeInput(category.getDescription());
        
        // 实际存储未经彻底清理的数据
        category.setTitle(safeTitle);
        category.setDescription(safeDesc);
        
        categoryService.saveCategory(category);
        return "redirect:/categories";
    }

    /**
     * 输入清理函数（存在缺陷）
     * @param input 用户输入
     * @return 清理后的字符串
     */
    private String sanitizeInput(String input) {
        // 仅过滤简单标签，无法阻止复杂绕过
        if (input == null) return null;
        
        // 存在漏洞的清理逻辑
        return input.replaceAll("<(script|i?frame|body|html|img|form|input|meta|link|style)>", "[removed]");
    }
}

// Thymeleaf模板代码（位于templates/categories/manage.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Device Categories</title>
</head>
<body>
    <h1>Device Categories</h1>
    <div th:each="category : ${categories}">
        <h3 th:text="${category.title}">Category Title</h3>
        <p th:text="${category.description}">Description</p>
    </div>
    
    <form method="post">
        <input type="text" name="title" placeholder="Category Title">
        <textarea name="description" placeholder="Description"></textarea>
        <button type="submit">Create</button>
    </form>
</body>
</html>
*/

// 漏洞利用示例：
// 攻击者提交的payload：
// <img src=x onerror=alert(document.cookie)>
// 或
// <svg/onload=eval(location.hash.slice(1))>#<script>alert(1)</script>
// 当管理员查看分类列表时，恶意脚本将在其浏览器上下文中执行
// 影响范围：所有访问分类管理页面的用户