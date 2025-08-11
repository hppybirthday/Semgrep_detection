package com.example.inventory.controller;

import com.example.inventory.service.ProductService;
import com.example.inventory.dto.ProductDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
@Tag(name = "ProductController", description = "商品管理接口")
public class ProductController {
    @Autowired
    private ProductService productService;

    @Operation(summary = "批量删除商品")
    @DeleteMapping("/batchDelete")
    public String batchDeleteProducts(@RequestParam("ids") List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return "参数错误";
        }
        try {
            productService.deleteProducts(ids);
            return "删除成功";
        } catch (Exception e) {
            return "删除失败: " + e.getMessage();
        }
    }
}

package com.example.inventory.service;

import com.example.inventory.mapper.ProductMapper;
import com.example.inventory.model.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    public void deleteProducts(List<Long> ids) {
        if (ids == null || ids.size() == 0) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        
        // 漏洞点：将ID列表转换为字符串拼接至SQL语句
        StringBuilder idBuilder = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            idBuilder.append(ids.get(i));
            if (i < ids.size() - 1) {
                idBuilder.append(",");
            }
        }
        
        // 错误的业务逻辑校验（仅校验非空但未验证数据有效性）
        if (idBuilder.length() == 0) {
            throw new IllegalArgumentException("无效ID格式");
        }
        
        productMapper.deleteProducts(idBuilder.toString());
    }
}

package com.example.inventory.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;

import java.util.List;

@Mapper
public interface ProductMapper {
    @Delete({"<script>",
        "DELETE FROM products WHERE id IN (${ids})",
        "</script>"})
    void deleteProducts(@Param("ids") String ids);
    
    // 模拟其他业务逻辑
    @Select("SELECT * FROM products WHERE id IN (${ids})")
    List<Product> getProductsByIds(@Param("ids") String ids);
}

package com.example.inventory.model;

public class Product {
    private Long id;
    private String name;
    private Double price;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public Double getPrice() { return price; }
    public void setPrice(Double price) { this.price = price; }
}