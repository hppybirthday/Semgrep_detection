import java.io.*;
import java.util.*;

// 银行交易实体类
class Transaction implements Serializable {
    private static final long serialVersionUID = 1L;
    private String accountNumber;
    private double amount;
    private Date timestamp;

    public Transaction(String accountNumber, double amount) {
        this.accountNumber = accountNumber;
        this.amount = amount;
        this.timestamp = new Date();
    }

    // 模拟交易处理逻辑
    public void execute() {
        System.out.println("[SYSTEM] Processing transaction...");
        System.out.println("Account: " + accountNumber);
        System.out.println("Amount: $" + amount);
    }
}

// 交易处理服务类
class TransactionService {
    // 不安全的反序列化操作
    public void handleTransaction(InputStream input) {
        try (ObjectInputStream ois = new ObjectInputStream(input)) {
            Object obj = ois.readObject();
            if (obj instanceof Transaction) {
                ((Transaction) obj).execute();
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Transaction processing failed: " + e.getMessage());
        }
    }
}

// 模拟银行服务端
class BankServer {
    public static void main(String[] args) {
        System.out.println("=== Vulnerable Banking System ===");
        
        // 模拟攻击者构造的恶意输入流
        byte[] maliciousPayload = Base64.getDecoder().decode(
            "rO0ABXNyAC5qYXZhLnV0aWwuU2Nhb3JfX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX1......" // 实际攻击中为精心构造的序列化payload
        );
        
        // 模拟处理客户端请求
        TransactionService service = new TransactionService();
        service.handleTransaction(new ByteArrayInputStream(maliciousPayload));
    }
}