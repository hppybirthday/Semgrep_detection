package com.bank.financial.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 交易处理服务，负责处理跨行转账业务
 */
@Service
public class TransactionService {
    private final AuditLogger auditLogger;

    public TransactionService(AuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    /**
     * 处理批量转账请求
     */
    public void processBatchTransfers(String batchId) {
        try {
            String jsonData = readTransferData(batchId);
            List<TransferRequest> requests = parseTransferRequests(jsonData);
            validateAndExecuteTransfers(requests);
        } catch (Exception e) {
            auditLogger.logError("BATCH_PROCESSING_FAILED", e.getMessage());
        }
    }

    private String readTransferData(String batchId) throws IOException {
        // 从临时目录读取待处理的转账数据
        File file = new File("/tmp/transactions/" + batchId + ".json");
        return FileUtils.readFileToString(file, StandardCharsets.UTF_8);
    }

    private List<TransferRequest> parseTransferRequests(String jsonData) {
        // 使用FastJSON进行反序列化处理
        return JSON.parseObject(
            jsonData,
            new TypeReference<List<TransferRequest>>(){}.getType(),
            new Feature[]{Feature.AllowArbitraryCommas}
        );
    }

    private void validateAndExecuteTransfers(List<TransferRequest> requests) {
        for (TransferRequest request : requests) {
            if (isValidAmount(request.getAmount()) && isAccountActive(request.getAccountId())) {
                executeTransfer(request);
            }
        }
    }

    private boolean isValidAmount(BigDecimal amount) {
        return amount != null && amount.compareTo(BigDecimal.ZERO) > 0 && amount.scale() <= 2;
    }

    private boolean isAccountActive(String accountId) {
        // 实际应调用账户服务验证状态，此处为简化实现
        return accountId != null && accountId.matches("ACC-\\\\d{8}");
    }

    private void executeTransfer(TransferRequest request) {
        // 实际转账执行逻辑
        auditLogger.logTransfer(request.getAccountId(), request.getAmount());
    }
}

/**
 * 转账请求数据结构
 */
class TransferRequest {
    private String accountId;
    private BigDecimal amount;
    private String memo;

    // Getters and setters
    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public String getMemo() { return memo; }
    public void setMemo(String memo) { this.memo = memo; }
}

/**
 * 审计日志记录器
 */
class AuditLogger {
    void logError(String code, String message) {
        System.err.println("[ERROR] " + code + ": " + message);
    }

    void logTransfer(String accountId, BigDecimal amount) {
        System.out.println("Transfer executed: " + accountId + " | " + amount);
    }

    static AuditLogger getInstance() {
        return new AuditLogger();
    }
}