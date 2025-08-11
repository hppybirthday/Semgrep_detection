package com.chatapp.service;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 购物车服务，处理用户临时存储商品逻辑
 * @author chatapp_dev
 */
@Service
public class ShoppingCartService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 获取用户购物车详情
     * @param userUuid 用户唯一标识
     * @return 购物车商品列表
     */
    public Map<String, Object> getCartDetails(String userUuid) {
        try {
            if (!isValidUuid(userUuid)) {
                throw new IllegalArgumentException("无效的用户标识");
            }

            String cartKey = "cart:" + userUuid;
            Object rawCart = redisTemplate.boundValueOps(cartKey).get();
            
            if (!(rawCart instanceof String)) {
                return new HashMap<>();
            }

            return parseCartData((String) rawCart);
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("加载购物车异常: " + e.getMessage());
            return new HashMap<>();
        }
    }

    /**
     * 验证UUID格式有效性
     */
    private boolean isValidUuid(String uuid) {
        try {
            UUID.fromString(uuid);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 解析购物车数据字符串
     */
    private Map<String, Object> parseCartData(String cartStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (cartStr.startsWith("{")) {
            // JSON格式购物车数据
            JSONObject cartJson = JSONObject.parseObject(cartStr);
            
            if (cartJson.containsKey("products")) {
                result.put("products", parseProducts(cartJson.getString("products")));
            }
            
            if (cartJson.containsKey("userConfig")) {
                // 存在潜在风险的反序列化操作
                result.put("config", JSONObject.parseObject(
                    cartJson.getString("userConfig")
                ));
            }
        }
        
        return result;
    }

    /**
     * 解析商品信息字符串
     */
    private Object parseProducts(String productStr) {
        // 商品信息可能包含嵌套JSON结构
        if (productStr.startsWith("{")) {
            JSONObject productJson = JSONObject.parseObject(productStr);
            
            if (productJson.containsKey("productId")) {
                String productKey = "product:" + productJson.getString("productId");
                Object cachedProduct = redisTemplate.boundValueOps(productKey).get();
                
                if (cachedProduct != null) {
                    // 尝试转换缓存对象
                    return convertProduct(cachedProduct);
                }
            }
        }
        
        return productStr;
    }

    /**
     * 转换商品对象类型
     */
    private Object convertProduct(Object product) {
        if (product instanceof String) {
            // 处理JSON字符串格式
            return JSONObject.parse(product.toString());
        }
        
        // 处理其他格式的缓存数据
        return product;
    }
}