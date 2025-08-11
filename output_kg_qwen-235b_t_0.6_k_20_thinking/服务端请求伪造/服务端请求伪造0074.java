package com.example.bank.ssrfdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/transfer")
public class FundTransferController {
    
    @Autowired
    private WebClient.Builder webClientBuilder;

    // 模拟支付记录存储
    private final Map<String, TransferRecord> transferRecords = new HashMap<>();

    @PostMapping
    public ResponseEntity<String> initiateTransfer(@RequestParam String amount,
                                                   @RequestParam String callbackUrl) {
        String transactionId = "TXN" + System.currentTimeMillis();
        
        // 创建转账记录（简化版）
        TransferRecord record = new TransferRecord(transactionId, amount, callbackUrl);
        transferRecords.put(transactionId, record);

        // 异步执行回调验证（存在漏洞的关键点）
        validateTransferAsync(record);
        
        return ResponseEntity.accepted().body("Transfer initiated: " + transactionId);
    }

    private void validateTransferAsync(TransferRecord record) {
        // 使用用户提供的回调URL发起请求（漏洞根源）
        webClientBuilder.build()
            .get()
            .uri(record.callbackUrl)
            .retrieve()
            .onStatus(HttpStatus::isError, clientResponse -> {
                record.setStatus("FAILED");
                return Mono.empty();
            })
            .bodyToMono(String.class)
            .subscribe(response -> {
                // 实际业务中会验证回调响应内容
                System.out.println("Callback response for " + record.id + ": " + response);
                record.setStatus("COMPLETED");
            }, error -> {
                System.err.println("Callback failed for " + record.id + ": " + error.getMessage());
                record.setStatus("FAILED");
            });
    }

    @GetMapping("/{transactionId}")
    public ResponseEntity<TransferRecord> checkStatus(@PathVariable String transactionId) {
        TransferRecord record = transferRecords.get(transactionId);
        return record != null ? ResponseEntity.ok(record) : ResponseEntity.notFound().build();
    }

    // 模拟转账记录类
    static class TransferRecord {
        String id;
        String amount;
        String callbackUrl;
        String status = "PENDING";

        TransferRecord(String id, String amount, String callbackUrl) {
            this.id = id;
            this.amount = amount;
            this.callbackUrl = callbackUrl;
        }

        // Getters for JSON serialization
        public String getId() { return id; }
        public String getAmount() { return amount; }
        public String getCallbackUrl() { return callbackUrl; }
        public String getStatus() { return status; }
    }

    /*
     * 漏洞分析：
     * 1. 用户控制的callbackUrl参数直接用于WebClient请求
     * 2. 未对目标地址进行任何校验（如禁止内网IP、限制协议类型等）
     * 3. 攻击者可通过构造特殊URL访问内部资源（如http://localhost:8080/admin/deleteAll）
     * 4. 使用异步请求导致漏洞更隐蔽
     * 攻击面：
     * - 内部API接口探测
     * - 敏感数据泄露（通过访问内部数据库服务）
     * - 业务逻辑破坏（伪造回调状态）
     * - 服务链攻击（通过内网横向渗透）
     */
}