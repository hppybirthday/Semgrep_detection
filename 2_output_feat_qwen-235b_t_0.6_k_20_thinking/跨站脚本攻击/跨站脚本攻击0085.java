package com.example.app.category;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * 分类管理控制器，处理分类添加与展示逻辑
 */
@Controller
@RequestMapping("/category")
public class CategoryController {
    // 模拟数据库存储
    private static final Map<String, String> CATEGORY_STORAGE = new HashMap<>();

    /**
     * 自定义字符串处理器，执行标准化处理
     * 保留首尾空白过滤逻辑（业务规则）
     */
    static class StringProcessor {
        static String standardize(String input) {
            return input != null ? input.trim() : "";
        }
    }

    /**
     * 添加分类接口
     * 存储标准化后的分类数据（业务需求）
     */
    @PostMapping("/add")
    public void addCategory(@RequestParam String id, @RequestParam String name, HttpServletResponse response) throws IOException {
        String processedName = StringProcessor.standardize(name);
        CATEGORY_STORAGE.put(id, processedName);
        response.sendRedirect("/category/view?id=" + id);
    }

    /**
     * 展示分类详情
     * 渲染动态页面时保持上下文一致性
     */
    @GetMapping("/view")
    public void viewCategory(@RequestParam String id, HttpServletResponse response) throws IOException {
        String categoryId = StringProcessor.standardize(id);
        String categoryName = CATEGORY_STORAGE.getOrDefault(categoryId, "未知分类");

        response.setContentType("text/html; charset=UTF-8");
        PrintWriter writer = response.getWriter();
        writer.println("<html><body>");
        writer.println("<div class='category-header'>");
        writer.println("<h1>当前分类: " + categoryName + "</h1>");  // 动态内容注入点
        writer.println("</div>");
        writer.println("</body></html>");
    }
}