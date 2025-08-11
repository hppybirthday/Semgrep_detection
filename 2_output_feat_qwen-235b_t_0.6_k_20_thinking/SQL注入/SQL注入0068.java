package com.example.ecommerce.controller;

import com.example.ecommerce.common.ApiResponse;
import com.example.ecommerce.common.PageRequest;
import com.example.ecommerce.service.ProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Tag(name = "商品管理", description = "商品信息查询接口")
@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @Operation(summary = "商品分页查询")
    @GetMapping
    public ApiResponse<Map<String, Object>> getProducts(
            @Parameter(description = "查询条件") @RequestParam Map<String, String> params,
            PageRequest pageRequest) {
        // 构造查询参数并执行分页查询
        return ApiResponse.success(productService.getProducts(params, pageRequest));
    }
}