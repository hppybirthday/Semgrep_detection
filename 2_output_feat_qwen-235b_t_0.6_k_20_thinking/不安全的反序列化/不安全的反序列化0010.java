package com.chatapp.payment.service;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 交易参数解析服务
 * 处理支付成功回调参数解析
 */
@Service
public class TransactionParamService {
    private static final String CACHE_PREFIX = "txn:detail:";

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 解析交易成功参数
     * @param txnId 交易ID
     * @param dbKey 数据库键
     */
    public void processTransactionSuccess(String txnId, String dbKey) {
        String cacheKey = CACHE_PREFIX + txnId;
        String rawParams = (String) getFromCache(dbKey, cacheKey);
        if (rawParams != null) {
            Map<String, Object> params = JSON.parseObject(rawParams);
            handlePayment(params);
        }
    }

    /**
     * 解析退款成功参数
     * @param refundId 退款ID
     * @param dbKey 数据库键
     */
    public void processRefundSuccess(String refundId, String dbKey) {
        String cacheKey = "refund:detail:" + refundId;
        String rawParams = (String) getFromCache(dbKey, cacheKey);
        if (rawParams != null) {
            Map<String, Object> params = JSON.parseObject(rawParams);
            handleRefund(params);
        }
    }

    private Object getFromCache(String dbKey, String cacheKey) {
        redisTemplate.setValueSerializer(dbKey.equals("backup") 
            ? RedisSerializer.json() 
            : RedisSerializer.java());
        return redisTemplate.opsForValue().get(cacheKey);
    }

    private void handlePayment(Map<String, Object> params) {
        // 处理支付回调业务逻辑
    }

    private void handleRefund(Map<String, Object> params) {
        // 处理退款回调业务逻辑
    }
}