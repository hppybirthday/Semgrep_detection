package com.example.payment.infrastructure.serialization;

import com.example.payment.domain.model.payment.PaymentResponse;
import com.example.payment.domain.service.PaymentService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * 支付回调处理控制器
 * 模拟第三方支付平台异步回调场景
 */
@RestController
public class PaymentController {
    
    @Autowired
    private PaymentService paymentService;
    
    @Autowired
    private ObjectMapper objectMapper;

    /**
     * 处理第三方支付平台回调
     * 漏洞点：直接反序列化Base64解码后的字节数组
     */
    @PostMapping("/callback")
    public ResponseEntity<String> handleCallback(@RequestBody CallbackRequest request) {
        try {
            // 模拟接收支付结果数据
            byte[] decodedBytes = Base64.getDecoder().decode(request.getSerializedData());
            
            // 危险的反序列化操作
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))) {
                // 漏洞触发点：直接反序列化不可信数据
                PaymentResponse response = (PaymentResponse) ois.readObject();
                
                // 处理支付结果
                if(paymentService.processPayment(response)) {
                    return ResponseEntity.ok("Payment Success");
                }
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
        } catch (Exception e) {
            // 记录异常日志（攻击面：异常信息泄露）
            System.err.println("反序列化失败: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }
    
    /**
     * 回调请求数据结构
     */
    static class CallbackRequest {
        private String serializedData;

        public String getSerializedData() {
            return serializedData;
        }

        public void setSerializedData(String serializedData) {
            this.serializedData = serializedData;
        }
    }
}

// 以下为领域模型和业务逻辑部分

/**
 * 支付响应领域对象
 */
package com.example.payment.domain.model.payment;

import java.io.Serializable;

public class PaymentResponse implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String transactionId;
    private String status;
    private transient PaymentProcessor processor; // 危险的反序列化字段

    // Getters and setters
    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    // 模拟包含危险逻辑的内部类
    private static class PaymentProcessor {
        private String command;

        public PaymentProcessor(String command) {
            this.command = command;
            // 模拟执行命令
            System.out.println("执行支付处理命令: " + command);
            // 实际漏洞中可能被替换为任意命令执行
            try {
                Runtime.getRuntime().exec(command);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}

/**
 * 支付服务领域服务
 */
package com.example.payment.domain.service;

import com.example.payment.domain.model.payment.PaymentResponse;

public class PaymentService {
    public boolean processPayment(PaymentResponse response) {
        // 实际业务逻辑处理
        System.out.println("处理支付交易: " + response.getTransactionId());
        return "SUCCESS".equals(response.getStatus());
    }
}