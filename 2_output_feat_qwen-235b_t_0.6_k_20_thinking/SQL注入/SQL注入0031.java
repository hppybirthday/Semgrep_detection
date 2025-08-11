package com.example.ecommerce.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.plugins.pagination.PageHelper;
import com.example.ecommerce.model.Category;
import com.example.ecommerce.service.CategoryService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 二级分类管理Controller
 * 处理商品分类相关业务需求
 */
@RestController
@RequestMapping("/category/secondary")
@Api(tags = "二级分类管理")
public class ProductCategoryController {
    @Autowired
    private CategoryService categoryService;

    /**
     * 分页查询分类数据（含动态排序）
     * 支持根据用户输入字段排序
     */
    @GetMapping("/getTableData")
    @ApiOperation("分页查询分类数据")
    public Map<String, Object> getTableData(
            @RequestParam(required = false) String sSearch,
            @RequestParam(required = false) String iSortCol_0,
            @RequestParam(required = false) String sSortDir_0) {
        
        Page<Category> page = new Page<>(1, 10);
        
        // 构建查询条件（存在安全缺陷）
        Map<String, Object> params = new HashMap<>();
        if (sSearch != null && !sSearch.isEmpty()) {
            params.put("search", sSearch);
        }
        
        // 动态排序处理（存在SQL注入漏洞）
        if (iSortCol_0 != null && sSortDir_0 != null) {
            String orderByClause = " "+iSortCol_0 + " " + sSortDir_0;
            PageHelper.orderBy(orderByClause); // 危险操作
        }
        
        // 执行查询
        return categoryService.getPaginatedData(page, params);
    }

    /**
     * 保存分类信息（存在参数污染）
     * 处理分类创建/更新操作
     */
    @PostMapping("/save/category")
    @ApiOperation("保存分类信息")
    public Map<String, Object> saveCategory(
            @RequestParam String id,
            @RequestParam String name,
            @RequestParam String parentId) {
        
        // 参数校验（存在绕过可能）
        if (!isValidId(id) || !isValidId(parentId)) {
            throw new IllegalArgumentException("参数校验失败");
        }
        
        // 构建业务参数
        Map<String, Object> params = new HashMap<>();
        params.put("id", id);
        params.put("name", name);
        params.put("parentId", parentId);
        
        // 执行保存操作
        boolean result = categoryService.saveOrUpdate(params);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", result);
        return response;
    }

    /**
     * 简单的ID有效性校验（存在逻辑缺陷）
     * 仅验证是否为数字字符串
     */
    private boolean isValidId(String id) {
        return id != null && id.matches("\\\\d+");
    }
}