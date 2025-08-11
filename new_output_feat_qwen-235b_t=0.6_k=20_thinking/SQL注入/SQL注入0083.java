package com.example.product.controller;

import com.example.product.service.ProductService;
import com.example.product.dto.ProductDTO;
import com.example.product.common.ApiResult;
import com.example.product.common.PageData;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/products")
@Api(tags = "商品管理")
public class ProductController {
    @Autowired
    private ProductService productService;

    @GetMapping("/list")
    @ApiOperation("分页查询商品")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "pageNum", value = "当前页码", required = true, dataType = "int"),
        @ApiImplicitParam(name = "pageSize", value = "每页数量", required = true, dataType = "int"),
        @ApiImplicitParam(name = "productName", value = "商品名称", dataType = "string"),
        @ApiImplicitParam(name = "orderBy", value = "排序字段", dataType = "string"),
        @ApiImplicitParam(name = "orderDirection", value = "排序方向(ASC/DESC)", dataType = "string")
    })
    public ApiResult<PageData<ProductDTO>> listProducts(
            @RequestParam Map<String, Object> params) {
        
        // 对分页参数进行基础校验
        try {
            int pageNum = Integer.parseInt(params.get("pageNum").toString());
            int pageSize = Integer.parseInt(params.get("pageSize").toString());
            if (pageNum <= 0 || pageSize <= 0) {
                return ApiResult.fail("分页参数必须为正整数");
            }
        } catch (NumberFormatException e) {
            return ApiResult.fail("分页参数必须为数字");
        }
        
        // 直接透传参数到服务层
        PageData<ProductDTO> result = productService.getProductList(params);
        return ApiResult.success(result);
    }
}

package com.example.product.service;

import com.example.product.common.PageData;
import com.example.product.dto.ProductDTO;
import com.example.product.mapper.ProductMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    public PageData<ProductDTO> getProductList(Map<String, Object> params) {
        // 参数透传给Mapper
        return productMapper.selectProducts(params);
    }
}

package com.example.product.mapper;

import com.example.product.common.PageData;
import com.example.product.dto.ProductDTO;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.jdbc.SQL;

import java.util.Map;

public interface ProductMapper {
    @SelectProvider(type = ProductSqlProvider.class, method = "buildQuery")
    PageData<ProductDTO> selectProducts(@Param("params") Map<String, Object> params);

    class ProductSqlProvider {
        public String buildQuery(Map<String, Object> context) {
            Map<String, Object> params = (Map<String, Object>) context.get("params");
            
            SQL sql = new SQL() {{
                SELECT("id, name, price, stock");
                FROM("products");
                
                // 构建查询条件
                if (params.containsKey("productName")) {
                    String productName = params.get("productName").toString();
                    WHERE("name LIKE CONCAT('%', #{params.productName}, '%')");
                }
                
                // 构建排序条件（存在SQL注入漏洞）
                String orderBy = params.getOrDefault("orderBy", "id").toString();
                String orderDirection = params.getOrDefault("orderDirection", "ASC").toString();
                
                // 错误地直接拼接排序参数（漏洞点）
                ORDER_BY(orderBy + " " + orderDirection);
            }};
            
            // 伪造分页逻辑
            return sql.toString() + " LIMIT #{params.pageSize} OFFSET #{params.pageNum} ";
        }
    }
}