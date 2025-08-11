package com.example.product.controller;

import com.example.product.service.ProductService;
import com.example.product.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @DeleteMapping("/batch")
    public String batchDelete(@RequestBody DeleteRequest request) {
        if (request.getIds().isEmpty()) {
            return "No IDs provided";
        }
        
        // 将字符串ID列表转换为逗号分隔的SQL IN子句
        String idList = String.join(",", request.getIds());
        
        try {
            productService.deleteProducts(idList);
            return "Deletion successful";
        } catch (Exception e) {
            return "Deletion failed: " + e.getMessage();
        }
    }
}

package com.example.product.service;

import com.example.product.dao.ProductDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ProductService {
    @Autowired
    private ProductDAO productDAO;

    public void deleteProducts(String idList) {
        // 模拟业务逻辑检查
        if (idList == null || idList.trim().isEmpty()) {
            throw new IllegalArgumentException("Invalid ID list");
        }
        
        // 错误的输入验证（存在绕过可能）
        if (!idList.matches("[0-9,\\\\s]+")) {
            throw new IllegalArgumentException("Only numeric IDs allowed");
        }
        
        // 将验证后的ID列表传递给DAO层
        productDAO.deleteProducts(idList);
    }
}

package com.example.product.dao;

import org.beetl.sql.annotation.Sql;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class ProductDAO {
    @Autowired
    private SQLManager sqlManager;

    @Sql("DELETE FROM products WHERE id IN (${idList})")
    public void deleteProducts(String idList) {
        // 通过原生SQL拼接执行删除操作
        sqlManager.execute(this.getClass(), idList);
    }
}

package com.example.product.dto;

import java.util.List;

public class DeleteRequest {
    private List<String> ids;

    public List<String> getIds() {
        return ids;
    }

    public void setIds(List<String> ids) {
        this.ids = ids;
    }
}