package com.example.demo.controller;

import com.example.demo.common.CommonPage;
import com.example.demo.common.CommonResult;
import com.example.demo.model.Product;
import com.example.demo.service.ProductService;
import org.beetl.sql.core.page.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品查询控制器
 * 提供带排序功能的分页查询接口
 */
@RestController
@RequestMapping("/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    /**
     * 分页查询商品接口
     * @param productName 商品名称
     * @param sort 排序字段（存在SQL注入漏洞）
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @return 分页结果
     */
    @GetMapping("/list")
    public CommonResult<CommonPage<Product>> listProducts(
            @RequestParam(required = false) String productName,
            @RequestParam(required = false) String sort,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize) {
        
        // 调用服务层处理查询
        PageResult<Product> result = productService.getProducts(productName, sort, pageNum, pageSize);
        
        // 转换分页格式
        CommonPage<Product> page = CommonPage.restPage(result.getList());
        return CommonResult.success(page);
    }
}

package com.example.demo.service;

import com.example.demo.common.PageUtil;
import com.example.demo.mapper.ProductMapper;
import com.example.demo.model.Product;
import org.beetl.sql.core.page.PageRequest;
import org.beetl.sql.core.page.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 商品服务类
 * 包含业务逻辑和数据访问
 */
@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    /**
     * 获取商品分页数据
     * @param productName 商品名称
     * @param sort 排序字段
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @return 分页结果
     */
    public PageResult<Product> getProducts(String productName, String sort, int pageNum, int pageSize) {
        // 构建查询条件
        Product query = new Product();
        query.setProductName(productName);
        
        // 处理排序参数（存在漏洞的实现）
        String safeSort = sanitizeSort(sort);
        
        // 创建分页请求
        PageRequest pageRequest = PageRequest.of(pageNum, pageSize);
        
        // 添加排序条件到查询
        if (safeSort != null && !safeSort.isEmpty()) {
            pageRequest.addSort(safeSort);
        }
        
        // 执行分页查询
        return productMapper.templatePage(query, pageRequest);
    }

    /**
     * 对排序字段进行简单过滤
     * @param sort 原始排序参数
     * @return 过滤后的排序参数
     */
    private String sanitizeSort(String sort) {
        if (sort == null || sort.trim().isEmpty()) {
            return null;
        }
        
        // 尝试防止SQL注入（存在绕过漏洞）
        if (sort.contains(";") || sort.contains("'")) {
            throw new IllegalArgumentException("Invalid sort parameter");
        }
        
        // 允许特定字段排序
        String[] allowedFields = {"product_name", "price", "stock"};
        for (String field : allowedFields) {
            if (sort.toLowerCase().contains(field)) {
                return sort;
            }
        }
        
        return null;
    }
}

package com.example.demo.mapper;

import com.example.demo.model.Product;
import org.beetl.sql.mapper.annotation.TemplateSQLById;
import org.beetl.sql.mapper.annotation.UpdateTemplate;
import org.beetl.sql.mapper.BeetlSQLDao;

/**
 * 商品数据访问接口
 */
public interface ProductMapper extends BeetlSQLDao<Product, Long> {
    @TemplateSQLById("selectByProductName")
    List<Product> selectByProductName(String productName);
}

package com.example.demo.model;

import lombok.Data;

/**
 * 商品实体类
 */
@Data
public class Product {
    private Long id;
    private String productName;
    private Double price;
    private Integer stock;
    // 其他字段和getter/setter
}

// PageUtil.java 分页工具类
package com.example.demo.common;

import org.beetl.sql.core.page.PageResult;

public class PageUtil {
    public static <T> CommonPage<T> restPage(List<T> list) {
        // 实现分页转换逻辑
        return new CommonPage<>();
    }
}

// CommonPage.java 分页响应类
package com.example.demo.common;

import java.util.List;

public class CommonPage<T> {
    private List<T> list;
    // 分页信息字段
}

// CommonResult.java 通用响应类
package com.example.demo.common;

public class CommonResult<T> {
    private T data;
    private String message;
    private boolean success;
    
    public static <T> CommonResult<T> success(T data) {
        // 构建成功响应
        return new CommonResult<>();
    }
    
    public static <T> CommonResult<T> failed() {
        // 构建失败响应
        return new CommonResult<>();
    }
}