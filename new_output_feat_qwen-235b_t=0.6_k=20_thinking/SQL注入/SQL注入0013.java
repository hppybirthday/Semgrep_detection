package com.example.app.controller;

import com.example.app.service.FavoriteService;
import com.example.app.dto.FavoriteResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/favorites")
public class FavoriteController {
    @Autowired
    private FavoriteService favoriteService;

    @GetMapping("/products")
    public List<FavoriteResponse> getFavoriteProducts(@RequestParam String userIds) {
        // 对输入参数进行简单清洗（存在安全缺陷）
        String sanitized = userIds.replaceAll("\\\\s+", "");
        return favoriteService.getFavorites(sanitized);
    }
}

package com.example.app.service;

import com.example.app.mapper.FavoriteMapper;
import com.example.app.dto.FavoriteResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FavoriteServiceImpl implements FavoriteService {
    @Autowired
    private FavoriteMapper favoriteMapper;

    @Override
    public List<FavoriteResponse> getFavorites(String sanitizedIds) {
        // 错误地信任清洗后的输入
        validateInput(sanitizedIds);
        return favoriteMapper.findFavorites(sanitizedIds);
    }

    private void validateInput(String input) {
        // 误导性的安全检查：仅检查空值但未过滤恶意内容
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Input cannot be empty");
        }
    }
}

package com.example.app.mapper;

import com.example.app.dto.FavoriteResponse;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FavoriteMapper {
    @Select({"<script>",
      "SELECT p.product_id, p.name, p.price ",
      "FROM favorites f ",
      "JOIN products p ON f.product_id = p.product_id ",
      "WHERE f.user_id IN (${sanitizedIds}) ",
      "GROUP BY p.product_id",
      "</script>"})
    List<FavoriteResponse> findFavorites(String sanitizedIds);
}

package com.example.app.dto;

public class FavoriteResponse {
    private String productId;
    private String name;
    private double price;

    // Getters and setters
    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public double getPrice() { return price; }
    public void setPrice(double price) { this.price = price; }
}