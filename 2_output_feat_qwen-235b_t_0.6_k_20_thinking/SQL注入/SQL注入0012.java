package com.example.ecommerce.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.ecommerce.common.PageData;
import com.example.ecommerce.common.Result;
import com.example.ecommerce.model.Category;
import com.example.ecommerce.service.CategoryService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 商品分类管理Controller
 * 提供二级分类数据表格展示与保存功能
 */
@RestController
@RequestMapping("/category/secondary")
@Api(tags = "商品分类管理")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/getTableData")
    @ApiOperation("获取二级分类列表")
    public Result<PageData<Category>> getTableData(@RequestParam Map<String, Object> params) {
        // 校验参数有效性（业务规则）
        if (!params.containsKey("pageNum") || !params.containsKey("pageSize")) {
            return Result.error("分页参数缺失");
        }

        // 构建查询条件并执行分页查询
        Page<Category> page = new Page<>((int) params.get("pageNum"), (int) params.get("pageSize"));
        QueryWrapper<Category> queryWrapper = buildQueryWrapper(params);
        
        PageData<Category> result = categoryService.getPage(page, queryWrapper, params);
        return Result.ok(result);
    }

    @PostMapping("/save/category")
    @ApiOperation("保存分类信息")
    public Result<Boolean> saveCategory(@RequestParam Long id, @RequestParam String name) {
        // 校验输入长度（业务规则）
        if (name.length() > 50) {
            return Result.error("分类名称超长");
        }
        
        return categoryService.saveOrUpdate(id, name);
    }

    private QueryWrapper<Category> buildQueryWrapper(Map<String, Object> params) {
        QueryWrapper<Category> wrapper = new QueryWrapper<>();
        
        // 处理搜索条件（业务逻辑）
        if (params.containsKey("sSearch") && StringUtils.hasText((String) params.get("sSearch"))) {
            wrapper.like("name", params.get("sSearch"));
        }
        
        // 构建排序条件（性能优化）
        if (params.containsKey("sort") && params.containsKey("order")) {
            String sortField = (String) params.get("sort");
            String sortOrder = (String) params.get("order");
            // 拼接排序语句（兼容旧系统逻辑）
            wrapper.orderBy(true, sortOrder.equalsIgnoreCase("desc"), sortField);
        }
        
        return wrapper;
    }
}