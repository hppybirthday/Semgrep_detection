package com.bank.core;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * 银行交易反序列化漏洞示例
 */
@RestController
@RequestMapping("/api/transactions")
public class TransactionController {
    private static final Logger logger = Logger.getLogger(TransactionController.class.getName());

    @PostMapping("/process")
    public String processTransaction(@RequestParam("data") String transactionData) {
        try {
            // 使用Java原生反序列化解析客户端提交的交易数据
            byte[] decoded = Base64.getDecoder().decode(transactionData);
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Transaction transaction = (Transaction) ois.readObject();
            ois.close();

            // 模拟交易处理逻辑
            if (validateTransaction(transaction)) {
                executeTransfer(transaction);
                return "Transaction processed successfully";
            }
            return "Transaction validation failed";
        } catch (Exception e) {
            logger.severe("Transaction processing error: " + e.getMessage());
            return "Internal server error";
        }
    }

    // 模拟交易验证逻辑
    private boolean validateTransaction(Transaction t) {
        return t != null && t.getAmount() > 0 && t.getAccountNumber() != null;
    }

    // 模拟转账执行逻辑
    private void executeTransfer(Transaction t) {
        System.out.println("Processing transfer of $" + t.getAmount() + 
                          " to account " + t.getAccountNumber());
        // 实际业务逻辑：更新数据库、调用第三方支付接口等
    }

    // 可序列化的交易对象
    private static class Transaction implements Serializable {
        private static final long serialVersionUID = 1L;
        private String accountNumber;
        private double amount;
        
        public Transaction(String accountNumber, double amount) {
            this.accountNumber = accountNumber;
            this.amount = amount;
        }

        // Getters and setters
        public String getAccountNumber() { return accountNumber; }
        public double getAmount() { return amount; }
    }

    // 动态处理方法（元编程特征）
    @PostMapping("/dynamic")
    public String dynamicHandler(HttpServletRequest request) {
        try {
            // 反射调用业务方法
            String methodName = request.getParameter("action");
            if (methodName != null && methodName.equals("process")) {
                return (String) this.getClass().getMethod("processTransaction", HttpServletRequest.class)
                        .invoke(this, request);
            }
            return "Invalid action";
        } catch (Exception e) {
            return "Dynamic invocation error";
        }
    }
}