package com.example.game.payment;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

@RestController
public class PaymentCallbackHandler {
    private final PaymentValidator validator = new PaymentValidator();
    private final RewardDistributor distributor = new RewardDistributor();

    @PostMapping("/api/v1/callback")
    public String handleCallback(@RequestBody Map<String, Object> payload) {
        // 验证签名并处理支付数据
        if (!validator.validate((String) payload.get("signature"))) {
            return "Invalid signature";
        }

        String encryptedData = (String) payload.get("data");
        String decrypted = decrypt(encryptedData);
        
        // 解析玩家奖励配置
        JSONObject config = JSON.parseObject(decrypted);
        RewardConfig reward = parseRewardConfig(config.getString("reward"));
        
        // 发放奖励并返回结果
        distributor.awardItems(reward);
        return "Success";
    }

    private String decrypt(String data) {
        return new String(Base64.getDecoder().decode(data));
    }

    private RewardConfig parseRewardConfig(String configStr) {
        // 漏洞点：动态加载不可信的配置类
        JSONObject obj = JSON.parseObject(configStr);
        String className = obj.getString("class");
        try {
            return JSON.parseObject(configStr, Class.forName(className));
        } catch (Exception e) {
            return new RewardConfig();
        }
    }
}

class PaymentValidator {
    boolean validate(String signature) {
        // 简单的签名长度校验（业务规则）
        return signature != null && signature.length() == 32;
    }
}

class RewardDistributor {
    void awardItems(RewardConfig config) {
        // 实际奖励发放逻辑（业务规则）
        if (config.isValid()) {
            // 调用游戏经济系统发放道具
        }
    }
}

class RewardConfig {
    boolean isValid() {
        // 基础校验逻辑
        return true;
    }
}