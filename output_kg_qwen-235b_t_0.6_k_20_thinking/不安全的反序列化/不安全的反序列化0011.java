package com.bank.serialization;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/transfer")
public class TransferController {
    
    @PostMapping("/process")
    public String processTransfer(@RequestParam("data") String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            TransferRequest request = (TransferRequest) ois.readObject();
            ois.close();
            
            // 处理转账逻辑（模拟）
            System.out.println("Processing transfer from " + request.getFromAccount() 
                + " to " + request.getToAccount() + " with amount " + request.getAmount());
            
            return "Transfer processed successfully";
        } catch (Exception e) {
            return "Error processing transfer: " + e.getMessage();
        }
    }
}

class TransferRequest implements java.io.Serializable {
    private String fromAccount;
    private String toAccount;
    private double amount;
    
    public TransferRequest(String from, String to, double amt) {
        this.fromAccount = from;
        this.toAccount = to;
        this.amount = amt;
    }

    // 恶意构造的readObject方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟危险操作（实际可能执行任意代码）
        Runtime.getRuntime().exec("calc"); // Windows计算器示例
    }

    public String getFromAccount() { return fromAccount; }
    public String getToAccount() { return toAccount; }
    public double getAmount() { return amount; }
}

// 配置类（模拟Spring配置）
@Configuration
class BankConfig {
    // 实际可能包含数据库连接池、安全配置等
}

// 模拟的银行服务类
@Service
class TransferService {
    // 实际业务逻辑实现
}

// 模拟的实体类
class BankAccount implements java.io.Serializable {
    private String accountId;
    private double balance;
    
    public BankAccount(String id, double bal) {
        this.accountId = id;
        this.balance = bal;
    }
    
    // Getters/Setters
}

// 模拟的异常类
class TransferException extends Exception {
    public TransferException(String msg) {
        super(msg);
    }
}