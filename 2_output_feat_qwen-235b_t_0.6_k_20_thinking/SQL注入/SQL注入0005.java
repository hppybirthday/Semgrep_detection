package com.example.taskmanager.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.taskmanager.service.CategoryService;
import com.example.taskmanager.model.Category;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "CategoryController", description = "任务分类管理")
@RestController
@RequestMapping("/category/secondary")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @Operation(summary = "分页查询分类")
    @GetMapping("/getTableData")
    public Page<Category> getTableData(
            @RequestParam(required = false) String sSearch,
            @RequestParam Integer pageNum,
            @RequestParam Integer pageSize,
            @RequestParam String order,
            @RequestParam String sort) {
        // 构建查询条件
        return categoryService.queryCategories(sSearch, pageNum, pageSize, order, sort);
    }

    @Operation(summary = "保存分类信息")
    @PostMapping("/save/category")
    public Boolean saveCategory(
            @RequestParam Long id,
            @RequestParam String name,
            @RequestParam Long userId,
            @RequestParam Integer valueId,
            @RequestParam Integer sort,
            @RequestParam String order) {
        // 更新分类信息
        return categoryService.updateCategory(id, name, userId, valueId, sort, order);
    }
}

// Service层代码模拟
package com.example.taskmanager.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.taskmanager.mapper.CategoryMapper;
import com.example.taskmanager.model.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CategoryService {
    @Autowired
    private CategoryMapper categoryMapper;

    public Page<Category> queryCategories(String sSearch, Integer pageNum, Integer pageSize, String order, String sort) {
        // 构造动态排序条件
        String orderBy = String.format("%s %s", order, sort);
        Page<Category> page = new Page<>(pageNum, pageSize);
        // 使用PageHelper进行动态排序
        return categoryMapper.selectPage(page, "", orderBy);
    }

    public Boolean updateCategory(Long id, String name, Long userId, Integer valueId, Integer sort, String order) {
        // 构建更新参数
        Map<String, Object> params = Map.of(
            "id", id,
            "name", name,
            "userId", userId,
            "valueId", valueId,
            "sort", sort,
            "order", order
        );
        return categoryMapper.updateCategory(params) > 0;
    }
}

// Mapper层代码模拟
package com.example.taskmanager.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.taskmanager.model.Category;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.Map;

public interface CategoryMapper extends BaseMapper<Category> {
    @Select({"<script>",
        "SELECT * FROM task_category WHERE 1=1",
        "<if test='search != null and search != ""> AND name LIKE CONCAT('%', #{search}, '%') </if>",
        "ORDER BY ${orderBy}",
        "</script>"})
    Page<Category> selectPage(Page<Category> page, @Param("search") String sSearch, @Param("orderBy") String orderBy);

    int updateCategory(@Param("id") Long id, @Param("name") String name, @Param("userId") Long userId,
                      @Param("valueId") Integer valueId, @Param("sort") Integer sort, @Param("order") String order);
}