package com.bank.financialsystem;

import java.io.*;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * 银行交易回调处理基类
 * 高抽象建模风格设计
 */
public abstract class AbstractTransactionCallbackHandler {
    protected static final Logger logger = Logger.getLogger(AbstractTransactionCallbackHandler.class.getName());

    /**
     * 处理支付平台回调数据
     * @param callbackData 回调原始数据
     * @return 处理结果
     */
    public abstract TransactionResult handleCallback(String callbackData);

    /**
     * 反序列化交易数据
     * @param encodedData 序列化数据
     * @return 反序列化对象
     * @throws Exception 反序列化异常
     */
    protected TransactionData deserializeTransaction(String encodedData) throws Exception {
        byte[] data = Base64.getDecoder().decode(encodedData);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 不安全的反序列化操作
            Object obj = ois.readObject();
            if (!(obj instanceof TransactionData)) {
                throw new IllegalArgumentException("Invalid transaction data type");
            }
            return (TransactionData) obj;
        }
    }

    /**
     * 交易数据基类
     */
    public static class TransactionData implements Serializable {
        private String transactionId;
        private double amount;
        private String accountNumber;
        // 省略getter/setter
    }

    /**
     * 交易结果返回类
     */
    public static class TransactionResult {
        private boolean success;
        private String message;
        // 省略getter/setter
    }
}

/**
 * 具体实现类 - 存在漏洞的回调处理器
 */
public class VulnerableCallbackHandler extends AbstractTransactionCallbackHandler {
    @Override
    public TransactionResult handleCallback(String callbackData) {
        TransactionResult result = new TransactionResult();
        try {
            TransactionData data = deserializeTransaction(callbackData);
            // 模拟交易处理逻辑
            logger.info("Processing transaction: " + data.transactionId);
            result.setSuccess(true);
            result.setMessage("Transaction processed successfully");
        } catch (Exception e) {
            logger.severe("Transaction processing failed: " + e.getMessage());
            result.setSuccess(false);
            result.setMessage("Error processing transaction");
        }
        return result;
    }

    public static void main(String[] args) {
        // 模拟攻击示例（实际应通过网络请求触发）
        VulnerableCallbackHandler handler = new VulnerableCallbackHandler();
        // 攻击载荷示例（此处仅为示意，实际攻击数据需要特殊构造）
        String maliciousPayload = "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAJGAApsb2FkRmFjdG9ySQAJbW9kaWZpZWRBZAAAAHh3BAAAAAdwdAAMbWFsbGljaW91cyBjAG14";
        handler.handleCallback(maliciousPayload);
    }
}