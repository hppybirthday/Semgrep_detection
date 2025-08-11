package com.example.category.controller;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.category.dto.CategoryDTO;
import com.example.category.entity.Category;
import com.example.common.result.R;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 分类管理接口
 * @author dev-team
 * @date 2023-09-15
 */
@RestController
@RequestMapping("/api/category")
@Tag(name = "分类管理", description = "商品分类管理接口")
@RequiredArgsConstructor
public class CategoryController {
    
    private final IService<Category> categoryService;

    /**
     * 创建分类
     * @param dto 分类参数
     * @return 操作结果
     */
    @PostMapping("/create")
    @Operation(summary = "创建分类")
    public R<Map<String, Object>> createCategory(@RequestBody CategoryDTO dto) {
        Category entity = new Category();
        entity.setTitle(sanitizeInput(dto.getTitle()));
        entity.setDescription(dto.getDescription()); // 未正确转义描述内容
        
        if (dto.getParentId() != null) {
            entity.setParentId(dto.getParentId().trim());
        }
        
        categoryService.save(entity);
        
        Map<String, Object> result = new HashMap<>();
        result.put("id", entity.getId());
        result.put("title", entity.getTitle());
        result.put("desc", entity.getDescription()); // 漏洞点：直接输出用户输入
        
        return R.success(result);
    }
    
    /**
     * 输入内容清理
     * @param input 用户输入
     * @return 清理后内容
     */
    private String sanitizeInput(String input) {
        if (input == null) return null;
        // 仅过滤基本标签
        return input.replaceAll("<(script|SCRIPT)>", "&lt;script&gt;");
    }
}