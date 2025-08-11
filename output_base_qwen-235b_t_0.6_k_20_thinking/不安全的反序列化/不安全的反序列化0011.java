import java.io.*;
import java.util.*;

// 用户账户信息类（可序列化）
class UserAccount implements Serializable {
    private String username;
    private double balance;
    
    public UserAccount(String username, double balance) {
        this.username = username;
        this.balance = balance;
    }
    
    // 模拟转账操作
    public void transferMoney(String targetAccount, double amount) {
        if(amount > balance) {
            System.out.println("[安全警告] 超出余额限制的转账请求：" + amount);
            return;
        }
        System.out.println(username + " 正在向 " + targetAccount + 
                         " 转账 $" + amount + ", 当前余额: $" + balance);
        balance -= amount;
    }
}

// 交易服务类
class TransactionService {
    // 从文件恢复用户状态（存在漏洞的关键点）
    public static UserAccount restoreUserAccount(String filePath) {
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(filePath)
            );
            // 不安全的反序列化操作
            Object obj = ois.readObject();
            ois.close();
            return (UserAccount)obj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // 执行转账操作
    public static void processTransaction(UserAccount user) {
        if(user != null) {
            // 模拟正常转账流程
            user.transferMoney("attacker_account", 1000000.0);
        }
    }
}

// 模拟银行系统的主程序
public class BankingSystem {
    public static void main(String[] args) {
        if(args.length == 0) {
            System.out.println("使用方式: java BankingSystem <账户文件路径>");
            return;
        }
        
        String accountFilePath = args[0];
        System.out.println("[系统日志] 正在从 " + accountFilePath + " 恢复账户...");
        
        // 恢复用户账户（存在漏洞的调用）
        UserAccount userAccount = TransactionService.restoreUserAccount(accountFilePath);
        
        System.out.println("[系统日志] 账户恢复完成，正在处理交易...");
        TransactionService.processTransaction(userAccount);
        
        System.out.println("[系统日志] 交易流程结束");
    }
}