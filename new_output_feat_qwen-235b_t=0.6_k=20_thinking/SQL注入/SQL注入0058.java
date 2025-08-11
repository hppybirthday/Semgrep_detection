package com.crm.module.category.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.crm.module.category.dto.CategoryDTO;
import com.crm.module.category.service.CategoryService;
import com.crm.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/category/secondary")
public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/getTableData")
    public Result<IPage<CategoryDTO>> getTableData(@RequestParam("sSearch") String search,
                                                   @RequestParam("iDisplayStart") int offset,
                                                   @RequestParam("iDisplayLength") int limit,
                                                   @RequestParam("iSortCol_0") int sortCol,
                                                   @RequestParam("sSortDir_0") String sortDir) {
        try {
            Page<CategoryDTO> page = new Page<>(offset / limit + 1, limit);
            String[] orderFields = {"name", "created_time", "status"};
            String orderBy = orderFields[sortCol] + " " + (sortDir.equalsIgnoreCase("asc") ? "ASC" : "DESC");
            
            // 漏洞点：将用户输入直接拼接到SQL语句中
            IPage<CategoryDTO> result = categoryService.getCategorySecondary(page, search, orderBy);
            return Result.success(result);
        } catch (Exception e) {
            return Result.error("查询失败: " + e.getMessage());
        }
    }

    @PostMapping("/save/category")
    public Result<Boolean> saveCategory(@RequestParam("id") String id,
                                       @RequestParam("name") String name) {
        try {
            // 漏洞点：直接拼接SQL语句
            boolean result = categoryService.saveCategory(id, name);
            return Result.success(result);
        } catch (Exception e) {
            return Result.error("保存失败: " + e.getMessage());
        }
    }
}

package com.crm.module.category.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.service.IService;
import com.crm.module.category.dto.CategoryDTO;
import com.crm.module.category.mapper.CategoryMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CategoryService implements IService<CategoryDTO> {
    @Autowired
    private CategoryMapper categoryMapper;

    public IPage<CategoryDTO> getCategorySecondary(IPage<CategoryDTO> page, String search, String orderBy) {
        // 漏洞点：使用MyBatis Plus的orderBy方法直接拼接SQL片段
        return categoryMapper.selectPage(page, search, orderBy);
    }

    public boolean saveCategory(String id, String name) {
        // 漏洞点：使用BeetlSQL的updateTemplateById直接拼接字段值
        Map<String, Object> params = new HashMap<>();
        params.put("id", id);
        params.put("name", name);
        return categoryMapper.updateTemplateById(params) > 0;
    }
}

package com.crm.module.category.mapper;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.crm.module.category.dto.CategoryDTO;
import org.apache.ibatis.annotations.Param;
import org.beetl.sql.core.annotatoin.SqlResource;
import org.beetl.sql.core.mapper.BaseMapper;

@SqlResource("category.secondary")
public interface CategoryMapper extends BaseMapper<CategoryDTO> {
    IPage<CategoryDTO> selectPage(Page<CategoryDTO> page, @Param("search") String search, @Param("orderBy") String orderBy);
}

// resources/sql/category.secondary.sql
SELECT * FROM categories 
WHERE 1=1
<#if search??>
  AND (name LIKE '%${search}%' OR description LIKE '%${search}%')
</#if>
ORDER BY ${orderBy}