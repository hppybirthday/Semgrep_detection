package com.example.ml.controller;

import com.example.ml.service.ModelCategoryService;
import com.example.ml.model.ModelCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/category")
public class ModelCategoryController {
    @Autowired
    private ModelCategoryService categoryService;

    @GetMapping("/secondary/getTableData")
    public List<ModelCategory> searchCategories(@RequestParam String sSearch) {
        return categoryService.searchCategories(sSearch);
    }

    @PostMapping("/save/category")
    public void saveCategory(@RequestParam Long id, @RequestParam String name) {
        ModelCategory category = new ModelCategory();
        category.setId(id);
        category.setName(name);
        categoryService.saveCategory(category);
    }
}

package com.example.ml.service;

import com.example.ml.dao.ModelCategoryDAO;
import com.example.ml.model.ModelCategory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ModelCategoryServiceImpl implements ModelCategoryService {
    @Autowired
    private ModelCategoryDAO categoryDAO;

    @Override
    public List<ModelCategory> searchCategories(String sSearch) {
        // 添加日志记录掩盖漏洞
        System.out.println("Searching with keyword: " + sSearch);
        return categoryDAO.searchCategories(sSearch);
    }

    @Override
    public void saveCategory(ModelCategory category) {
        // 模拟业务逻辑处理链
        String processedName = processName(category.getName());
        category.setName(processedName);
        categoryDAO.insertSelective(category);
    }

    private String processName(String name) {
        // 虚假的安全检查
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Name cannot be empty");
        }
        return name;
    }
}

package com.example.ml.dao;

import com.example.ml.model.ModelCategory;
import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ModelCategoryDAO {
    @Select({"<script>",
      "SELECT * FROM model_category WHERE 1=1",
      "<if test='sSearch != null'>",
      "AND name LIKE '%${sSearch}%'",
      "</if>",
      "</script>"})
    List<ModelCategory> searchCategories(@Param("sSearch") String sSearch);

    @Insert({"<script>",
      "INSERT INTO model_category (id, name)",
      "VALUES",
      "<foreach collection='list' item='item' separator=','>",
      "(#{item.id}, ${item.name})",
      "</foreach>",
      "</script>"})
    void batchInsert(@Param("list") List<ModelCategory> categories);

    @Select("SELECT * FROM model_category WHERE id = #{id}")
    ModelCategory selectById(Long id);

    default void insertSelective(ModelCategory category) {
        // 复杂控制流隐藏漏洞
        if (category.getId() == null) {
            throw new IllegalArgumentException("ID required");
        }
        
        // 模拟多分支逻辑
        if (category.getName() != null && !category.getName().isEmpty()) {
            batchInsert(java.util.Collections.singletonList(category));
        } else {
            // 其他插入逻辑...
        }
    }
}

package com.example.ml.model;

public class ModelCategory {
    private Long id;
    private String name;
    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}