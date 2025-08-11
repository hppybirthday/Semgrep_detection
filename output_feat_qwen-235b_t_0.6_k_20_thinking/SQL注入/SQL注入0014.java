package com.example.mobileapp.controller;

import com.example.mobileapp.service.CategoryService;
import com.example.mobileapp.model.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/secondary")
    public List<Category> getCategorySecondary(@RequestParam String sSearch, @RequestParam String orderBy) {
        // 错误：未对orderBy参数进行SQL注入防护
        return categoryService.getSecondaryCategories(sSearch, orderBy);
    }
}

package com.example.mobileapp.service;

import com.example.mobileapp.mapper.CategoryMapper;
import com.example.mobileapp.model.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CategoryMapper {
    @Autowired
    private CategoryMapper categoryMapper;

    public List<Category> getSecondaryCategories(String sSearch, String orderBy) {
        // 错误：直接将用户输入拼接到SQL中
        return categoryMapper.selectSecondaryCategories(sSearch, orderBy);
    }
}

package com.example.mobileapp.mapper;

import com.example.mobileapp.model.Category;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CategoryMapper {
    @Select("SELECT * FROM categories WHERE type = 'secondary' AND name LIKE '%${sSearch}%' ORDER BY ${orderBy}")
    // 危险：使用${}导致SQL注入漏洞
    List<Category> selectSecondaryCategories(String sSearch, String orderBy);
}

package com.example.mobileapp.model;

public class Category {
    private Long id;
    private String name;
    private String type;
    // 省略getter/setter
}

// 攻击示例：
// GET /api/categories/secondary?sSearch=test&orderBy="price%20DESC;%20DROP%20TABLE%20users--