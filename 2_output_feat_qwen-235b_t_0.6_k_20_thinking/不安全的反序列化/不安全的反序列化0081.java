package com.bank.payment.controller;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * 支付回调处理控制器
 */
@RestController
public class PaymentCallbackController {

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 处理第三方支付回调
     * @param body 回调数据
     */
    @PostMapping("/api/payment/notify")
    public String handlePaymentNotification(@RequestBody JSONObject body) {
        // 校验必要字段是否存在（业务规则）
        if (!body.containsKey("dbKey") || !body.containsKey("paymentData")) {
            return "Invalid request";
        }

        String dbKey = body.getString("dbKey");
        String paymentData = body.getString("paymentData");
        
        // 解析支付数据，存在不安全反序列化
        Object parsedData = resolvePaymentData(paymentData);
        
        // 构造Redis键并缓存数据
        String cacheKey = String.format("payment:details:%s", dbKey);
        redisTemplate.setValueSerializer(new org.springframework.data.redis.serializer.JdkSerializationRedisSerializer());
        redisTemplate.opsForValue().set(cacheKey, parsedData, 1, java.util.concurrent.TimeUnit.HOURS);
        
        return "Processed";
    }

    /**
     * 解析支付数据内容
     */
    private Object resolvePaymentData(String paymentData) {
        // 错误地直接反序列化不可信数据
        return com.alibaba.fastjson.JSON.parse(paymentData);
    }
}