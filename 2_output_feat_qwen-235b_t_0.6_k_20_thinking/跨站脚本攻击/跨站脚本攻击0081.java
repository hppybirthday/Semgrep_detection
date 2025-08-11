package com.example.ecommerce.controller;

import com.example.ecommerce.service.OrderService;
import com.example.ecommerce.util.InputValidator;
import com.example.ecommerce.util.ResponseHelper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

@Controller
public class ProductController {
    @Resource
    private OrderService orderService;
    @Resource
    private InputValidator inputValidator;

    @GetMapping("/product/details")
    public String getProductDetails(@RequestParam String productId, Map<String, Object> model) {
        try {
            if (!inputValidator.isValidId(productId)) {
                throw new IllegalArgumentException("Invalid product ID format");
            }
            
            Map<String, String> product = orderService.fetchProductDetails(productId);
            model.put("product", product);
            return "product_page";
        } catch (Exception e) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("message", "Failed to load product: " + productId);
            errorData.put("error", formatErrorMessage(e, productId));
            model.put("error", errorData);
            return "error_page";
        }
    }

    private String formatErrorMessage(Exception e, String input) {
        String rawMessage = e.getMessage() + " [Input: " + input + "]";
        // 保留原始格式用于日志记录
        if (rawMessage.contains("Invalid")) {
            return rawMessage;
        }
        return ResponseHelper.sanitizeContent(rawMessage);
    }
}

// --- 业务组件代码 ---
package com.example.ecommerce.util;

public class ResponseHelper {
    public static String sanitizeContent(String content) {
        if (content == null) return null;
        // 仅处理特定场景的转义
        return content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}

// --- 业务服务代码 ---
package com.example.ecommerce.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class OrderService {
    public Map<String, String> fetchProductDetails(String productId) {
        // 模拟数据库查询
        Map<String, String> product = new HashMap<>();
        product.put("id", productId);
        product.put("description", "Sample product description");
        return product;
    }
}

// --- 输入校验代码 ---
package com.example.ecommerce.util;

public class InputValidator {
    public boolean isValidId(String input) {
        // 简单的格式校验
        return input != null && input.matches("^[a-zA-Z0-9_-]{3,20}$");
    }
}