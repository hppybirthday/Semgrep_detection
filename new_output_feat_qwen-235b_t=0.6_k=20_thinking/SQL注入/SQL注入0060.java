package com.example.app.controller;

import com.example.app.service.ProductService;
import com.example.app.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @DeleteMapping("/delete")
    public Result deleteProducts(@RequestParam String[] ids) {
        if (ids == null || ids.length == 0) {
            return Result.error("Empty IDs");
        }
        
        // 检查ID格式是否为数字
        for (String id : ids) {
            if (!id.matches("\\\\d+")) {
                return Result.error("Invalid ID format");
            }
        }
        
        // 调用服务层删除
        try {
            productService.delete(ids);
            return Result.success("Deletion succeeded");
        } catch (Exception e) {
            return Result.error("Deletion failed: " + e.getMessage());
        }
    }
    
    @GetMapping("/search")
    public Result searchProducts(@RequestParam String keyword, 
                                @RequestParam(defaultValue = "id") String sort,
                                @RequestParam(defaultValue = "asc") String order) {
        if (keyword.isEmpty() || sort.isEmpty() || order.isEmpty()) {
            return Result.error("Parameters cannot be empty");
        }
        
        // 构造排序条件（存在漏洞）
        String sortOrder = sort + " " + order;
        List<?> results = productService.search(keyword, sortOrder);
        return Result.success(results);
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

    public void delete(String[] ids) {
        // 将ID数组转换为逗号分隔字符串（危险操作）
        String idList = String.join(",", ids);
        
        // 调用持久层执行删除（漏洞点）
        productMapper.deleteByIds(idList);
    }
    
    public List<Product> search(String keyword, String sortOrder) {
        // 构造动态查询（漏洞点）
        String condition = "name LIKE '%" + keyword + "%' ORDER BY " + sortOrder;
        return productMapper.search(condition);
    }
}

package com.example.app.mapper;

import com.example.app.model.Product;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface ProductMapper extends BaseMapper<Product> {
    // 使用MyBatis直接拼接SQL（危险设计）
    @Select("SELECT * FROM products WHERE ${condition}")
    List<Product> search(@Param("condition") String condition);
    
    // 自定义删除方法（漏洞根源）
    void deleteByIds(@Param("idList") String idList);
}

// MyBatis XML配置（片段）
<!-- <delete id="deleteByIds">
    DELETE FROM products WHERE id IN (${idList})
</delete> -->