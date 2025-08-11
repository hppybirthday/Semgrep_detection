package com.example.app.controller;

import com.example.app.service.ProductService;
import com.example.app.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @DeleteMapping("/batchDelete")
    public String batchDelete(@RequestBody DeleteRequest request) {
        if (request.getIds().isEmpty()) {
            return "ID列表不能为空";
        }
        
        // 将逗号分隔的字符串转换为List（存在安全漏洞）
        List<String> idList = List.of(request.getIds().split(","));
        
        // 调用服务层处理删除逻辑
        boolean result = productService.deleteProducts(idList);
        return result ? "删除成功" : "删除失败";
    }
}

package com.example.app.service;

import com.example.app.mapper.ProductMapper;
import com.example.app.model.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    public boolean deleteProducts(List<String> ids) {
        // 漏洞点：直接传递未经校验的ID列表
        List<Product> products = productMapper.getProductsByIds(ids);
        
        if (products.isEmpty()) {
            return false;
        }
        
        // 实际删除操作
        return productMapper.deleteProducts(ids) > 0;
    }
}

package com.example.app.mapper;

import com.example.app.model.Product;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface ProductMapper {
    // 漏洞关键点：使用${}进行SQL拼接（危险操作）
    List<Product> getProductsByIds(@Param("ids") List<String> ids);
    
    // 漏洞关键点：使用${}进行SQL拼接（危险操作）
    int deleteProducts(@Param("ids") List<String> ids);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.mapper.ProductMapper">
    <!-- 漏洞XML配置：动态SQL拼接 -->
    <select id="getProductsByIds" resultType="com.example.app.model.Product">
        SELECT * FROM products
        WHERE id IN
        <foreach collection="ids" item="id" open="(" separator="," close=")">
            ${id}
        </foreach>
    </select>

    <delete id="deleteProducts">
        DELETE FROM products
        WHERE id IN
        <foreach collection="ids" item="id" open="(" separator="," close=")">
            ${id}
        </foreach>
    </delete>
</mapper>

package com.example.app.dto;

import lombok.Data;

@Data
public class DeleteRequest {
    private String ids;
}

package com.example.app.model;

import lombok.Data;

@Data
public class Product {
    private Long id;
    private String name;
    private Double price;
}