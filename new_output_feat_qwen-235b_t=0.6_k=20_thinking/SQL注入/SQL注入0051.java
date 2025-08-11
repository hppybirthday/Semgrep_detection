package com.example.product.controller;

import com.example.product.service.ProductService;
import com.example.product.dto.CommonResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 商品管理Controller
 */
@RestController
@Tag(name = "ProductController", description = "商品管理")
@RequestMapping("/api/product")
public class ProductController {
    @Autowired
    private ProductService productService;

    @Operation(summary = "批量删除商品")
    @DeleteMapping("/delete")
    public CommonResult deleteProducts(
            @Parameter(name = "ids", description = "商品ID列表", required = true)
            @RequestParam("ids") List<Long> ids) {
        try {
            int count = productService.deleteProducts(ids);
            return CommonResult.success(count);
        } catch (Exception e) {
            return CommonResult.failed("删除失败: " + e.getMessage());
        }
    }
}

package com.example.product.service;

import com.example.product.mapper.ProductMapper;
import com.example.product.model.Product;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 商品服务实现类
 */
@Service
public class ProductService {
    @Autowired
    private ProductMapper productMapper;

    public int deleteProducts(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        
        // 漏洞点：错误地处理ID列表拼接
        String idList = ids.toString().replaceAll("\\\\[|\\\\]", "");
        
        // 误导性安全检查
        if (!SqlUtil.validateIdList(idList)) {
            throw new SecurityException("非法ID格式");
        }
        
        return productMapper.deleteProducts(idList);
    }
}

package com.example.product.mapper;

import org.apache.ibatis.annotations.Delete;
import org.springframework.stereotype.Repository;

/**
 * 商品数据访问层
 */
@Repository
public interface ProductMapper {
    /**
     * 漏洞点：使用拼接方式构造IN查询
     * 示例SQL: DELETE FROM product WHERE id IN (1,2,3)
     */
    @Delete({"<script>",
      "DELETE FROM product WHERE id IN (${ids})",
      "</script>"})
    int deleteProducts(String ids);
}

package com.example.product.util;

/**
 * SQL工具类（存在缺陷的实现）
 */
public class SqlUtil {
    /**
     * 误导性ID校验（存在绕过可能）
     */
    public static boolean validateIdList(String idList) {
        return idList != null && idList.matches("(\\\\d+,?)+");
    }

    /**
     * 错误的转义方法（仅用于order by）
     */
    public static String escapeOrderBySql(String value) {
        if (value == null) return null;
        return value.replaceAll("([;\\\\\\\\'])", "\\\\\\\\\\\\\\$1");
    }
}

// 模型类
package com.example.product.model;

public class Product {
    private Long id;
    private String name;
    private Double price;
    // 省略getter/setter
}

// 通用结果类
package com.example.product.dto;

public class CommonResult {
    private int code;
    private String message;
    private Object data;

    public static CommonResult success(Object data) {
        CommonResult result = new CommonResult();
        result.setCode(200);
        result.setMessage("成功");
        result.setData(data);
        return result;
    }

    public static CommonResult failed(String message) {
        CommonResult result = new CommonResult();
        result.setCode(500);
        result.setMessage(message);
        return result;
    }
    // 省略getter/setter
}