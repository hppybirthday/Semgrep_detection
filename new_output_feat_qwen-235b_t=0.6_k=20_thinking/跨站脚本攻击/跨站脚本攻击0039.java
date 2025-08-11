package com.example.bigdata.controller;

import com.example.bigdata.service.CategoryService;
import com.example.bigdata.model.Category;
import com.example.bigdata.util.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author Dev Team
 * @date 2023-11-15
 */
@Controller
@RequestMapping("/categories")
public class CategoryController {
    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @GetMapping("/manage")
    public String showCategories(@RequestParam(required = false) String parentId,
                                 @RequestParam(required = false) String backParentId,
                                 @RequestParam(required = false) String categoryLevel,
                                 Model model, HttpServletRequest request) {
        // 恶意参数通过HTML上下文注入
        String safeParentId = sanitizeInput(parentId);
        String safeBackParent = sanitizeInput(backParentId);
        
        // 错误的转义逻辑：仅处理categoryLevel参数
        if (categoryLevel != null) {
            categoryLevel = StringUtils.escapeHtml(categoryLevel);
        }

        // 存储型XSS触发点：将未经充分验证的参数写入模板
        model.addAttribute("parentId", safeParentId);
        model.addAttribute("backParentId", safeBackParent);
        model.addAttribute("categoryLevel", categoryLevel);

        // 大数据分页处理
        int pageSize = 50;
        int currentPage = 1;
        
        try {
            String pageStr = request.getParameter("page");
            if (pageStr != null && !pageStr.isEmpty()) {
                currentPage = Integer.parseInt(pageStr);
            }
        } catch (NumberFormatException e) {
            // 记录无效分页参数但继续执行
            System.err.println("Invalid page number: " + e.getMessage());
        }

        List<Category> categories = categoryService.getCategories(
            currentPage, pageSize, parentId, categoryLevel);
            
        // 错误的模板渲染方式
        model.addAttribute("categories", categories);
        return "category_management"; // Thymeleaf模板未启用自动转义
    }

    @PostMapping("/update")
    public String updateCategory(@RequestParam String id,
                                 @RequestParam String name,
                                 @RequestParam String metadata) {
        // 存储型XSS写入点：将用户输入直接存储到数据库
        Category category = new Category();
        category.setId(id);
        category.setName(name); // 未验证名称字段
        category.setMetadata(metadata); // 元数据字段存储原始HTML
        
        categoryService.updateCategory(category);
        return "redirect:/categories/manage";
    }

    // 错误的输入清理实现
    private String sanitizeInput(String input) {
        if (input == null) return "";
        
        // 表面的清理逻辑：仅移除部分标签
        String result = input.replace("<script>", "").replace("</script>", "");
        
        // 安全日志记录（但未阻止攻击）
        if (!result.equals(input)) {
            System.out.println("Potential XSS attempt blocked in sanitizeInput");
        }
        
        return result;
    }
}

// Thymeleaf模板示例（category_management.html）
// <div th:text="${parentId}"> <!-- 漏洞点：直接输出用户输入 -->
// <div th:text="${backParentId}"> <!-- 漏洞点：绕过清理函数 -->
// <div th:utext="${categoryLevel}"> <!-- 危险的原始HTML输出 -->
// <span th:text="${category.name}"> <!-- 存储型XSS触发点 -->
// <div th:utext="${category.metadata}"> <!-- 持久化恶意内容 -->