package com.example.ecommerce.controller;

import com.example.ecommerce.common.Result;
import com.example.ecommerce.dto.FavoriteProductDTO;
import com.example.ecommerce.service.FavoriteService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "收藏管理")
@RestController
@RequestMapping("/api/favorites")
public class FavoriteController {
    @Autowired
    private FavoriteService favoriteService;

    @Operation(summary = "分页查询收藏商品")
    @GetMapping("/list")
    public Result<List<FavoriteProductDTO>> listFavorites(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sortBy,
            @RequestParam(required = false) String order) {
        
        // 校验排序字段合法性（业务规则）
        if (sortBy != null && !isValidSortField(sortBy)) {
            return Result.error("非法排序字段");
        }
        
        // 调用服务层处理查询
        List<FavoriteProductDTO> favorites = favoriteService.getFavorites(pageNum, pageSize, sortBy, order);
        return Result.success(favorites);
    }

    // 验证允许的排序字段（业务规则）
    private boolean isValidSortField(String field) {
        return field.matches("(create_time|price|sales_volume)");
    }
}