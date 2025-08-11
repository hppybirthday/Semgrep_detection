package com.bank.finance;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/transactions")
public class TransactionProcessor {
    
    @PostMapping("/process")
    public String handleTransaction(@RequestParam("data") String base64Data, HttpServletRequest request) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Transaction transaction = (Transaction) ois.readObject();
            ois.close();
            
            // 模拟银行交易处理逻辑
            if ("TRANSFER".equals(transaction.getType())) {
                processTransfer(transaction);
            } else if ("LOAN".equals(transaction.getType())) {
                processLoan(transaction);
            }
            
            return "Transaction processed successfully";
        } catch (Exception e) {
            return "Transaction failed: " + e.getMessage();
        }
    }
    
    private void processTransfer(Transaction transaction) {
        System.out.println("Processing transfer: " + transaction.getAmount() + " to " + transaction.getRecipient());
    }
    
    private void processLoan(Transaction transaction) {
        System.out.println("Processing loan application for " + transaction.getAmount());
    }
    
    // 模拟银行交易对象
    public static class Transaction implements Serializable {
        private String type;
        private double amount;
        private String recipient;
        private String accountNumber;
        
        public String getType() { return type; }
        public double getAmount() { return amount; }
        public String getRecipient() { return recipient; }
        public String getAccountNumber() { return accountNumber; }
        
        // 模拟敏感操作
        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            // 模拟执行敏感操作
            if ("MALICIOUS".equals(type)) {
                Runtime.getRuntime().exec("calc"); // 模拟攻击代码
            }
        }
    }
}