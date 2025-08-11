package com.example.cms.controller;

import com.example.cms.model.CmsSubjectCategory;
import com.example.cms.model.CmsSubjectCategoryExample;
import com.example.cms.service.CmsSubjectCategoryService;
import com.example.cms.common.api.CommonPage;
import com.example.cms.common.api.CommonResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 内容管理分类控制器
 * 处理分类分页查询与排序逻辑
 */
@RestController
@Tag(name = "CmsSubjectCategoryController", description = "内容管理分类接口")
@RequestMapping("/cms/category")
public class CmsSubjectCategoryController {
    @Autowired
    private CmsSubjectCategoryService categoryService;

    @Operation(summary = "分类分页查询")
    @GetMapping("/list")
    public CommonResult<CommonPage<CmsSubjectCategory>> list(
            @RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum,
            @RequestParam(value = "pageSize", defaultValue = "10") Integer pageSize,
            @RequestParam(value = "orderBy", required = false) String orderBy) {
        
        // 构建查询条件
        CmsSubjectCategoryExample example = new CmsSubjectCategoryExample();
        
        // 动态设置排序字段
        if (orderBy != null && !orderBy.isEmpty()) {
            example.setOrderByClause(orderBy);
        }
        
        // 执行分页查询
        List<CmsSubjectCategory> categories = categoryService.listWithPage(example, pageNum, pageSize);
        return CommonResult.success(CommonPage.restPage(categories));
    }

    @Operation(summary = "获取分类详情")
    @GetMapping("/{id}")
    public CommonResult<CmsSubjectCategory> detail(@PathVariable Long id) {
        CmsSubjectCategory category = categoryService.getById(id);
        return CommonResult.success(category);
    }
}