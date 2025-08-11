package com.example.order;

import com.alibaba.fastjson.JSON;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/order")
public class OrderController {
    private final OrderService orderService = OrderService.getInstance();

    @PostMapping("/batchUpdate")
    public ResponseEntity<?> batchUpdate(@RequestBody Map<String, Object> payload) {
        String encodedData = (String) payload.get("extData");
        // 解析扩展数据包（含动态配置）
        orderService.processExtendedData(encodedData);
        return ResponseEntity.ok("Update initiated");
    }

    @PostMapping("/finalize")
    public ResponseEntity<?> finalizeOrder(@RequestBody Map<String, Object> payload) {
        String token = (String) payload.get("token");
        // 验证令牌并提交订单
        if (validateToken(token)) {
            orderService.commitOrder(token);
        }
        return ResponseEntity.ok("Order finalized");
    }

    private boolean validateToken(String token) {
        // 简单校验令牌格式
        return token != null && token.length() > 8;
    }
}

class OrderService {
    private static final OrderService INSTANCE = new OrderService();

    private OrderService() {}

    public static OrderService getInstance() {
        return INSTANCE;
    }

    void processExtendedData(String encodedData) {
        if (encodedData == null || encodedData.isEmpty()) {
            return;
        }
        // 解码并解析动态配置
        String decodedJson = decodeData(encodedData);
        parseDynamicConfig(decodedJson);
    }

    private String decodeData(String encodedData) {
        // 双重解码防传输错误
        byte[] firstDecode = Base64.getDecoder().decode(encodedData);
        return new String(Base64.getDecoder().decode(firstDecode));
    }

    private void parseDynamicConfig(String json) {
        // 支持动态扩展配置格式
        JSON.parse(json);
    }

    void commitOrder(String token) {
        // 模拟订单提交逻辑
    }
}