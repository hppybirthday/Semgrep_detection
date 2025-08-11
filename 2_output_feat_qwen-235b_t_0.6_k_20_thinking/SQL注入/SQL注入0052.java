package com.example.demo.controller;

import com.example.demo.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/product")
public class ProductController {
    @Autowired
    private ProductService productService;

    @DeleteMapping("/delete")
    public String deleteProducts(@RequestParam("ids") List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return "参数错误";
        }
        try {
            productService.batchDelete(ids);
            return "删除成功";
        } catch (Exception e) {
            return "删除失败: " + e.getMessage();
        }
    }
}

// com/example/demo/service/ProductService.java
package com.example.demo.service;

import com.example.demo.dao.ProductDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {
    @Autowired
    private ProductDao productDao;

    public void batchDelete(List<Long> ids) {
        if (ids.size() > 100) {
            throw new IllegalArgumentException("批量删除数量超限");
        }
        String idStr = ids.toString().replaceAll("\\\\[|\\\\]", "");
        productDao.deleteProducts(idStr);
    }
}

// com/example/demo/dao/ProductDao.java
package com.example.demo.dao;

import org.apache.ibatis.annotations.Delete;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductDao {
    @Delete({"<script>",
        "DELETE FROM products WHERE id IN (${ids})",
        "</script>"})
    void deleteProducts(String ids);
}

// application.yml配置
# mybatis配置
mybatis:
  mapper-locations: classpath:mapper/*.xml
  type-aliases-package: com.example.demo.model