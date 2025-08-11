package com.example.ecommerce.product.controller;

import com.example.ecommerce.product.service.ProductCategoryService;
import com.example.ecommerce.product.model.ProductCategory;
import com.example.ecommerce.common.api.CommonPage;
import com.example.ecommerce.common.api.CommonResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品分类管理Controller
 * @author commerce-team
 */
@RestController
@Tag(name = "ProductCategoryController", description = "商品分类管理")
@RequestMapping("/category/secondary")
public class ProductCategoryController {
    @Autowired
    private ProductCategoryService categoryService;

    @Operation(summary = "分页查询分类数据")
    @GetMapping("/getTableData")
    public CommonResult<CommonPage<ProductCategory>> getTableData(
        @RequestParam(value = "sSearch", required = false) String search,
        @RequestParam(value = "pageSize", defaultValue = "10") Integer pageSize,
        @RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum) {
        
        // 调用服务层处理带搜索的分页查询
        List<ProductCategory> result = categoryService.getPageData(search, pageSize, pageNum);
        CommonPage<ProductCategory> page = CommonPage.restPage(result);
        return CommonResult.success(page);
    }

    @Operation(summary = "保存分类信息")
    @PostMapping("/save/category")
    public CommonResult<Boolean> saveCategory(
        @RequestParam("id") Long id,
        @RequestBody ProductCategory category) {
        
        // 验证ID有效性
        if (id <= 0) {
            return CommonResult.failed("ID无效");
        }
        
        // 调用服务层保存数据
        boolean success = categoryService.saveCategoryInfo(id, category);
        return success ? CommonResult.success(true) : CommonResult.failed();
    }
}

// Service层实现
package com.example.ecommerce.product.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.ecommerce.product.mapper.ProductCategoryMapper;
import com.example.ecommerce.product.model.ProductCategory;
import com.example.ecommerce.product.service.ProductCategoryService;
import com.example.ecommerce.common.utils.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 商品分类服务实现类
 */
@Service
public class ProductCategoryServiceImpl implements ProductCategoryService {
    
    @Autowired
    private ProductCategoryMapper categoryMapper;

    @Override
    public List<ProductCategory> getPageData(String search, int pageSize, int pageNum) {
        // 构造分页查询条件
        QueryWrapper<ProductCategory> queryWrapper = new QueryWrapper<>();
        
        // 存在漏洞的搜索条件处理
        if (StringUtils.isNotBlank(search)) {
            // 错误地使用字符串拼接构造SQL片段（漏洞点）
            queryWrapper.apply("name like '%" + search + "%'");
        }
        
        // 执行分页查询
        return categoryMapper.selectPage(queryWrapper);
    }

    @Override
    public boolean saveCategoryInfo(Long id, ProductCategory category) {
        // 简单的输入验证（存在绕过可能）
        if (id == null || category == null || id <= 0) {
            return false;
        }
        
        // 直接更新记录（此处未使用漏洞参数）
        category.setId(id);
        return categoryMapper.updateById(category) > 0;
    }
}

// MyBatis Mapper接口
package com.example.ecommerce.product.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.ecommerce.product.model.ProductCategory;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductCategoryMapper extends BaseMapper<ProductCategory> {
    // 使用MyBatis-Plus内置方法，但getPageData中的QueryWrapper.apply导致漏洞
}