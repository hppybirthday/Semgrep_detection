package com.example.paymentservice.config;

import com.alibaba.fastjson.JSON;
import com.example.paymentservice.model.PaymentConfig;
import com.example.paymentservice.service.PaymentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/config")
public class PaymentConfigController {
    @Autowired
    private PaymentService paymentService;

    @PostMapping("/update")
    public String updateConfig(@RequestParam String params) {
        try {
            // 解析配置参数并更新支付策略
            List<PaymentConfig> configs = ConfigParser.stringToList(params);
            paymentService.updatePaymentConfigs(configs);
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
}

class ConfigParser {
    static List<PaymentConfig> stringToList(String jsonStr) {
        // 将JSON字符串转换为配置对象列表
        return JSON.parseArray(jsonStr, PaymentConfig.class);
    }
}

package com.example.paymentservice.model;

import lombok.Data;

@Data
public class PaymentConfig {
    private String configName;
    private int timeout;
    // 用于动态扩展的配置参数
    private ExtraParams extraParams;
}

class ExtraParams {
    // 保留未来扩展的参数结构
    private String paramKey;
    private String paramValue;
}

package com.example.paymentservice.service;

import com.example.paymentservice.model.PaymentConfig;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PaymentService {
    public void updatePaymentConfigs(List<PaymentConfig> configs) {
        // 验证配置有效性（示例校验）
        if (configs == null || configs.isEmpty()) {
            throw new IllegalArgumentException("配置不能为空");
        }
        
        // 实际业务处理逻辑
        for (PaymentConfig config : configs) {
            validateConfig(config);
            // 保存配置到持久化存储
            saveToDatabase(config);
        }
    }

    private void validateConfig(PaymentConfig config) {
        if (config.getTimeout() < 0) {
            throw new IllegalArgumentException("超时时间必须为正数");
        }
    }

    private void saveToDatabase(PaymentConfig config) {
        // 模拟数据库保存操作
    }
}