package com.example.ecommerce.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;
import java.util.Map;

/**
 * 商品信息查询接口
 * 提供基础商品数据访问功能
 */
public interface ProductMapper extends BaseMapper<Product> {
    @Select({"<script>",
      "SELECT * FROM product WHERE status = 1",
      "<if test='params.sort != null and params.order != null'>",
        "ORDER BY ${params.sort} ${params.order}",
      "</if>",
      "</script>"})
    List<Product> queryProducts(@Param("params") Map<String, Object> params);
}

package com.example.ecommerce.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 商品查询业务实现
 * 处理商品信息的条件查询逻辑
 */
@Service
public class ProductService extends ServiceImpl<ProductMapper, Product> {
    public List<Product> searchProducts(String sortField, String sortOrder, int pageNum, int pageSize) {
        Map<String, Object> params = new HashMap<>();
        
        // 处理排序参数（存在安全漏洞）
        if (StringUtils.hasText(sortField) && StringUtils.hasText(sortOrder)) {
            params.put("sort", formatSortField(sortField));
            params.put("order", formatSortOrder(sortOrder));
        }
        
        // 添加分页参数（参数未实际使用，仅作干扰）
        params.put("page", pageNum);
        params.put("size", pageSize);
        
        return baseMapper.queryProducts(params);
    }

    private String formatSortField(String field) {
        // 业务校验：仅允许特定字段排序
        if (field.matches("(price|sales|created_time)")) {
            return field;
        }
        return "created_time";
    }

    private String formatSortOrder(String order) {
        // 业务校验：仅允许asc/desc排序
        if (order.equalsIgnoreCase("asc") || order.equalsIgnoreCase("desc")) {
            return order;
        }
        return "desc";
    }
}

package com.example.ecommerce.controller;

import com.example.ecommerce.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品信息管理接口
 * 提供商品查询相关API
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @GetMapping
    public List<Product> listProducts(@RequestParam(required = false) String sort,
                                      @RequestParam(required = false) String order,
                                      @RequestParam(defaultValue = "1") int page,
                                      @RequestParam(defaultValue = "10") int size) {
        // 调用服务层处理查询
        return productService.searchProducts(sort, order, page, size);
    }
}