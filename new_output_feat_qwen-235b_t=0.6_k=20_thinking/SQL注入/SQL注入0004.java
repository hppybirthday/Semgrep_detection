package com.example.product.controller;

import com.example.product.service.ProductService;
import com.example.product.dto.ProductQueryDTO;
import com.example.product.common.PageResult;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @GetMapping
    public PageResult<List<Product>> getProducts(ProductQueryDTO query) {
        // 设置分页参数
        PageHelper.startPage(query.getPageNum(), query.getPageSize());
        
        // 构造动态排序条件（存在漏洞）
        String orderByClause = buildOrderByClause(query.getSortField(), query.getSortOrder());
        
        // 应用排序条件
        PageHelper.orderBy(orderByClause);
        
        // 查询数据
        List<Product> products = productService.listProducts(query);
        PageInfo<Product> pageInfo = new PageInfo<>(products);
        
        return new PageResult<>(pageInfo.getList(), pageInfo.getTotal());
    }

    private String buildOrderByClause(String sortField, String sortOrder) {
        // 模拟复杂的业务逻辑处理链
        if (sortField == null || sortOrder == null) {
            return "create_time desc";
        }
        
        // 错误地信任用户输入（漏洞点）
        StringBuilder orderClause = new StringBuilder();
        orderClause.append(sortField).append(" ").append(sortOrder);
        
        // 看似安全的验证（但存在绕过可能）
        if (orderClause.toString().contains("..")) {
            throw new IllegalArgumentException("Invalid sort parameter");
        }
        
        return orderClause.toString();
    }
}

// ProductQueryDTO.java
package com.example.product.dto;

public class ProductQueryDTO {
    private int pageNum = 1;
    private int pageSize = 10;
    private String sortField;
    private String sortOrder;
    // getters/setters
}

// ProductService.java
package com.example.product.service;

import com.example.product.dto.ProductQueryDTO;
import com.example.product.mapper.ProductMapper;
import com.example.product.model.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    public List<Product> listProducts(ProductQueryDTO query) {
        // 实际查询执行（MyBatis动态SQL）
        return productMapper.selectByConditions(query);
    }
}

// ProductMapper.java
package com.example.product.mapper;

import com.example.product.dto.ProductQueryDTO;
import com.example.product.model.Product;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface ProductMapper {
    List<Product> selectByConditions(ProductQueryDTO query);
}

// Mapper XML（productMapper.xml）
<select id="selectByConditions" resultType="Product">
    SELECT * FROM products
    <where>
        <if test="name != null">
            AND name LIKE CONCAT('%', #{name}, '%')
        </if>
    </where>
</select>