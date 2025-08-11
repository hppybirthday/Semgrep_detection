package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.engine.PageQuery;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/products")
public class ProductController {
    @Autowired
    private SQLManager sqlManager;

    @GetMapping
    public PageQuery<Product> getProducts(@RequestParam Map<String, String> params) {
        String sort = params.getOrDefault("sort", "id");
        String order = params.getOrDefault("order", "asc");
        int pageNum = Integer.parseInt(params.getOrDefault("page", "1"));
        int pageSize = Integer.parseInt(params.getOrDefault("size", "10"));
        
        // 漏洞点：直接拼接ORDER BY子句
        String sql = "SELECT * FROM products ORDER BY " + sort + " " + order +
                     " LIMIT " + ((pageNum - 1) * pageSize) + "," + pageSize;
        
        PageQuery<Product> page = new PageQuery<>();
        page.setQuery(sql);
        sqlManager.execute(page, Product.class);
        return page;
    }
    
    @DeleteMapping("/{id}")
    public void deleteProduct(@PathVariable String id) {
        // 漏洞点：直接拼接IN子句
        sqlManager.allMatchesUpdate("products", "DELETE FROM products WHERE id IN (" + id + ")");
    }
}

class Product {
    private Integer id;
    private String name;
    private Double price;
    // getters and setters
    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Double getPrice() { return price; }
    public void setPrice(Double price) { this.price = price; }
}