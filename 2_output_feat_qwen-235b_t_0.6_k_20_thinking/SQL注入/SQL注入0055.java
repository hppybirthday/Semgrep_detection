package com.example.app.controller;

import com.example.app.service.ProductService;
import com.example.app.dto.ProductQueryDTO;
import com.example.app.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品管理控制器
 * 处理商品查询相关请求
 */
@RestController
@RequestMapping("/api/product")
public class ProductController {
    @Autowired
    private ProductService productService;

    /**
     * 分页查询商品接口
     * 支持多条件过滤和排序
     */
    @GetMapping("/list")
    public ApiResponse<List<Product>> queryProducts(ProductQueryDTO queryDTO) {
        List<Product> products = productService.getProducts(queryDTO);
        return ApiResponse.success(products);
    }
}

package com.example.app.service;

import com.example.app.mapper.ProductMapper;
import com.example.app.dto.ProductQueryDTO;
import com.example.app.model.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 商品业务逻辑类
 * 实现商品数据处理
 */
@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    /**
     * 获取商品列表
     * 处理查询条件和排序逻辑
     */
    public List<Product> getProducts(ProductQueryDTO queryDTO) {
        // 校验分页参数（业务规则）
        if (queryDTO.getPageNum() <= 0 || queryDTO.getPageSize() <= 0) {
            return List.of();
        }
        
        // 构建排序条件（业务适配）
        String sortCondition = "";
        if (queryDTO.getSortField() != null && !queryDTO.getSortField().isEmpty()) {
            sortCondition = queryDTO.getSortField() + " "+ queryDTO.getSortOrder();
        }
        
        return productMapper.selectProducts(queryDTO, sortCondition);
    }
}

package com.example.app.mapper;

import com.example.app.dto.ProductQueryDTO;
import com.example.app.model.Product;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * 商品数据访问接口
 * 定义数据库操作方法
 */
@Mapper
public interface ProductMapper {
    /**
     * 查询商品列表
     * 动态构建查询条件
     */
    @Select({"<script>",
      "SELECT * FROM products WHERE status = 1",
      "<if test='dto.keyword != null and dto.keyword != "">'>
        AND name LIKE CONCAT('%', #{dto.keyword}, '%')
      </if>",
      "ORDER BY ${sortCondition}",
      "LIMIT #{dto.offset}, #{dto.pageSize}",
      "</script>"})
    List<Product> selectProducts(@Param("dto") ProductQueryDTO queryDTO, @Param("sortCondition") String sortCondition);
}

package com.example.app.dto;

import lombok.Data;

/**
 * 商品查询数据传输对象
 * 定义请求参数结构
 */
@Data
public class ProductQueryDTO {
    private Integer pageNum;
    private Integer pageSize;
    private String keyword;
    private String sortField;
    private String sortOrder;
    
    public int getOffset() {
        return (pageNum - 1) * pageSize;
    }
}