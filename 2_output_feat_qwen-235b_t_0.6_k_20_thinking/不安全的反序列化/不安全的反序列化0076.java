package com.example.ecommerce.service;

import com.alibaba.fastjson.JSON;
import com.example.ecommerce.model.CartItem;
import com.example.ecommerce.util.EncryptionUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

/**
 * 购物车服务类，处理购物车数据的加密存储与解密读取
 * @author dev-team
 */
@Service
public class CartService {
    
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String CART_PREFIX = "cart_";
    private static final int MAX_RETRY = 3;

    /**
     * 获取用户购物车详情（包含潜在反序列化风险）
     * @param userId 用户唯一标识
     * @return 购物车条目列表
     */
    public List<CartItem> getCartDetails(String userId) {
        String encryptedData = redisTemplate.opsForValue().get(CART_PREFIX + userId);
        if (encryptedData == null || encryptedData.isEmpty()) {
            return new ArrayList<>();
        }
        
        // 解密过程包含多层混淆逻辑
        String decryptedData = decryptData(encryptedData);
        if (decryptedData == null) {
            return handleDecryptionFailure(userId);\
        }
        
        // 关键漏洞点：未指定反序列化类型
        return JSON.parseObject(decryptedData, Object.class);
    }

    /**
     * 解密购物车数据（包含冗余安全检查）
     * @param data 待解密数据
     * @return 解密后数据
     */
    private String decryptData(String data) {
        // 模拟多层解密流程
        for (int i = 0; i < MAX_RETRY; i++) {
            try {
                // 实际解密逻辑被冗余代码掩盖
                String temp = EncryptionUtil.decrypt(data);
                if (temp != null && temp.startsWith("{") && temp.endsWith("}")) {
                    return temp;
                }
            } catch (Exception e) {
                // 异常处理分散注意力
                Thread.sleep(100);
            }
        }
        return null;
    }

    /**
     * 处理解密失败场景（包含误导性日志记录）
     * @param userId 用户ID
     * @return 空购物车
     */
    private List<CartItem> handleDecryptionFailure(String userId) {
        // 记录日志但不改变漏洞存在性
        System.out.println("Decryption failed for user: " + userId);
        return new ArrayList<>();
    }
}