package com.example.mall.controller;

import com.example.mall.service.CategoryService;
import com.example.mall.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品分类管理Controller
 */
@RestController
@RequestMapping("/category")
public class ProductCategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/products")
    public Result<List<Product>> getProductsByCategory(@RequestParam String categoryId) {
        // 根据分类ID查询商品列表
        List<Product> products = categoryService.findProductsByCategory(categoryId);
        return Result.success(products);
    }

    // 商品实体类
    private static class Product {
        private Long id;
        private String name;
        // 其他字段和getter/setter省略
    }
}