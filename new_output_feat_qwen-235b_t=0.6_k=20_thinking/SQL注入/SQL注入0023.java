package com.example.app.controller;

import com.example.app.common.PageResult;
import com.example.app.common.Result;
import com.example.app.model.Product;
import com.example.app.service.ProductService;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品管理控制器
 * @author dev-team
 */
@RestController
@RequestMapping("/api/product")
public class ProductController {
    @Autowired
    private ProductService productService;

    /**
     * 分页查询商品（含动态排序）
     * 攻击者可通过order参数注入恶意SQL
     */
    @GetMapping("/list")
    public Result<PageResult<List<Product>>> listProducts(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sort,
            @RequestParam(required = false) String order) {
        
        // 构造动态排序条件（存在漏洞的关键点）
        String orderByClause = "";
        if (sort != null && order != null) {
            // 直接拼接用户输入到排序语句（危险操作）
            // 示例：输入sort=1;DROP TABLE users; order=ASC
            // 将生成：1;DROP TABLE users; ASC
            orderByClause = sort + " " + order;
        }
        
        try {
            PageHelper.startPage(pageNum, pageSize);
            // 漏洞传递点：将拼接的排序参数传入MyBatis查询
            PageHelper.orderBy(orderByClause);
            
            List<Product> products = productService.getProducts();
            PageInfo<Product> pageInfo = new PageInfo<>(products);
            
            return Result.success(new PageResult<>(
                pageInfo.getList(),
                pageInfo.getTotal(),
                pageNum,
                pageSize
            ));
        } catch (Exception e) {
            // 通用异常处理掩盖真实错误信息
            return Result.error("查询失败，请稍后重试");
        }
    }
}

// Service层代码
package com.example.app.service;

import com.example.app.mapper.ProductMapper;
import com.example.app.model.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 商品服务实现
 * 看似安全的参数传递实际保留了注入风险
 */
@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    public List<Product> getProducts() {
        // MyBatis查询实际执行拼接后的SQL
        return productMapper.selectAll();
    }
}

// Mapper接口
package com.example.app.mapper;

import com.example.app.model.Product;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * MyBatis映射器
 * 使用基础查询配合PageHelper实现动态排序
 */
public interface ProductMapper {
    @Select("SELECT * FROM products")
    List<Product> selectAll();
}

// 配套实体类
package com.example.app.model;

import lombok.Data;

@Data
public class Product {
    private Long id;
    private String name;
    private Double price;
    private Integer stock;
}

// 分页响应封装类
package com.example.app.common;

import lombok.Data;

@Data
public class PageResult<T> {
    private T data;
    private Long total;
    private Integer pageNum;
    private Integer pageSize;
    
    public PageResult(T data, Long total, Integer pageNum, Integer pageSize) {
        this.data = data;
        this.total = total;
        this.pageNum = pageNum;
        this.pageSize = pageSize;
    }
}

// 通用响应类
package com.example.app.common;

import lombok.Data;

@Data
public class Result<T> {
    private Integer code;
    private String message;
    private T data;
    
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(200);
        result.setMessage("操作成功");
        result.setData(data);
        return result;
    }
    
    public static <T> Result<T> error(String message) {
        Result<T> result = new Result<>();
        result.setCode(500);
        result.setMessage(message);
        return result;
    }
}