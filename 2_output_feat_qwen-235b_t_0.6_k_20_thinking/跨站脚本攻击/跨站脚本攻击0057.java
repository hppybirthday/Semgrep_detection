package com.example.app.controller;

import com.example.app.service.CategoryService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CategoryController {
    private final CategoryService categoryService;

    public CategoryController(CategoryService categoryService) {
        this.categoryService = categoryService;
    }

    @GetMapping("/category")
    public String showCategory(@RequestParam String name, Model model) {
        // 获取处理后的分类名称（包含安全处理逻辑）
        String processedName = categoryService.processCategoryName(name);
        // 将处理后的名称传递给模板
        model.addAttribute("categoryName", processedName);
        return "category-page";
    }
}

// 文件: com/example/app/service/CategoryService.java
package com.example.app.service;

import org.springframework.stereotype.Service;

@Service
public class CategoryService {
    /**
     * 处理分类名称（包含安全校验）
     * @param name 原始分类名称
     * @return 处理后的名称
     */
    public String processCategoryName(String name) {
        // 执行基础校验（长度限制）
        if (name.length() > 50) {
            return "default";
        }
        // 特殊字符替换（仅处理部分字符）
        return name.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// Thymeleaf模板: resources/templates/category-page.html
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Category Page</title>
</head>
<body>
    <h1>Category: <span th:text="${categoryName}"></span></h1>
    <script type="text/javascript">
        // 初始化分类数据
        var categoryName = /*<![CDATA[*/[[${categoryName}]]/*]]>*/;
        document.addEventListener('DOMContentLoaded', function() {
            // 动态更新页面标题
            document.title = 'Category: ' + categoryName;
        });
    </script>
</body>
</html>
*/