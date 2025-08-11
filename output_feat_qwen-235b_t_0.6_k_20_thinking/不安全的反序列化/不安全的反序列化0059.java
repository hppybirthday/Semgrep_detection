package com.bank.financial;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class TradingSystem {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RiskManagement riskEngine = new RiskControl();
    
    @PostMapping("/depot/add")
    public ResponseEntity<String> addPosition(@RequestBody String jsonData) {
        try {
            PositionConfig config = JsonUtils.convertValue(jsonData, PositionConfig.class);
            if (riskEngine.validate(config)) {
                // 模拟持久化操作
                System.out.println("Position added: " + config.getAssetId());
                return ResponseEntity.ok("Success");
            }
            return ResponseEntity.badRequest().body("Risk validation failed");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Processing error");
        }
    }

    @PostMapping("/depot/update")
    public ResponseEntity<String> updatePosition(@RequestBody Map<String, Object> payload) {
        try {
            PositionUpdate update = parsePositionUpdate(payload);
            // 业务逻辑处理
            System.out.println("Position updated: " + update.getPositionId());
            return ResponseEntity.ok("Updated");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid update request");
        }
    }

    private PositionUpdate parsePositionUpdate(Map<String, Object> data) throws IOException {
        // 漏洞点：未验证类型直接转换
        return objectMapper.readValue(
            objectMapper.writeValueAsBytes(data),
            PositionUpdate.class
        );
    }

    // 高风险抽象类
    public static abstract class PositionConfig {
        public abstract String getAssetId();
    }

    // 恶意载荷示例类（攻击者构造）
    public static class MaliciousConfig extends PositionConfig {
        private String assetId;

        public MaliciousConfig() {
            try {
                // 模拟远程代码执行
                Runtime.getRuntime().exec("calc");
            } catch (Exception e) {
                // 静默失败
            }
        }

        @Override
        public String getAssetId() {
            return assetId;
        }
    }

    interface RiskManagement {
        boolean validate(PositionConfig config);
    }

    static class RiskControl implements RiskManagement {
        @Override
        public boolean validate(PositionConfig config) {
            // 风控逻辑（被绕过）
            return config.getAssetId() != null;
        }
    }

    static class PositionUpdate {
        private String positionId;
        // getters/setters
        public String getPositionId() { return positionId; }
        public void setPositionId(String id) { this.positionId = id; }
    }
}