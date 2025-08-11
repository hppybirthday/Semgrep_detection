package com.example.vulnerableapp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.function.Function;

@SpringBootApplication
@EnableCaching
public class VulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper(); // 不安全的反序列化配置
    }

    @RestController
    static class CartController {
        @Autowired
        private RedisAndLocalCache cartCache;

        @PostMapping("/depotHead/forceCloseBatch")
        public String processCart(@RequestBody Map<String, String> payload) {
            String cartId = payload.get("uuid");
            return cartCache.getCart(cartId).apply(cart -> {
                // 模拟业务逻辑处理
                return "Processed cart: " + cart.toString();
            });
        }
    }

    @Service
    static class RedisAndLocalCache {
        @Autowired
        private RedisTemplate<String, Object> redisCache;
        @Autowired
        private ObjectMapper objectMapper;

        public Function<Object, Object> getCart(String key) {
            return cached -> {
                if (cached == null) {
                    // 模拟从数据库加载
                    String redisData = (String) redisCache.opsForValue().get(key);
                    try {
                        // 不安全的反序列化操作
                        return objectMapper.readValue(redisData, Object.class);
                    } catch (Exception e) {
                        return new ShoppingCart();
                    }
                }
                return cached;
            };
        }
    }

    static class ShoppingCart {
        private Map<String, Integer> items;
        // 模拟恶意代码执行点
        private void readObject(java.io.ObjectInputStream in) {
            try {
                Runtime.getRuntime().exec("calc"); // 模拟RCE
            } catch (Exception e) {}
        }
    }
}