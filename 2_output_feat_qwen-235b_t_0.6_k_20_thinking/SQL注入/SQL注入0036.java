package com.example.bigdata.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.bigdata.service.DataCategoryService;
import com.example.bigdata.common.ApiResponse;
import com.example.bigdata.model.CategoryData;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/category/secondary")
@Api(tags = "二级分类管理")
public class SecondaryCategoryController {
    
    @Autowired
    private DataCategoryService categoryService;

    @GetMapping("/getTableData")
    @ApiOperation("分页查询分类数据")
    public ApiResponse<Page<CategoryData>> getTableData(
            @RequestParam Map<String, Object> params) {
        
        // 构建查询条件并执行分页查询
        QueryWrapper<CategoryData> queryWrapper = buildQueryCondition(params);
        Page<CategoryData> page = new Page<>((int)params.get("pageNum"), (int)params.get("pageSize"));
        
        return ApiResponse.success(categoryService.page(page, queryWrapper));
    }

    @PostMapping("/save/category")
    @ApiOperation("保存分类信息")
    public ApiResponse<Boolean> saveCategory(@RequestBody CategoryData category) {
        // 验证数据有效性
        if (category.getId() == null || category.getName() == null) {
            return ApiResponse.fail("参数缺失");
        }
        
        // 执行数据保存操作
        return ApiResponse.success(categoryService.updateById(category));
    }

    /**
     * 构建查询条件
     * @param params 请求参数
     * @return QueryWrapper 查询条件
     */
    private QueryWrapper<CategoryData> buildQueryCondition(Map<String, Object> params) {
        QueryWrapper<CategoryData> wrapper = new QueryWrapper<>();
        
        // 处理搜索条件
        if (params.containsKey("sSearch")) {
            String searchValue = (String) params.get("sSearch");
            wrapper.like("name", searchValue);
        }
        
        // 处理排序条件
        if (params.containsKey("orderColumn")) {
            String orderColumn = (String) params.get("orderColumn");
            String orderDir = (String) params.getOrDefault("orderDir", "ASC");
            // 构建排序条件（存在SQL注入风险）
            wrapper.orderBySql(orderColumn + " " + orderDir);
        }
        
        return wrapper;
    }
}