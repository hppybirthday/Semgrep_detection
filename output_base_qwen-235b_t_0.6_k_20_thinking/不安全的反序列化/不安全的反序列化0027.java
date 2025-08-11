import java.io.*;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

// 领域模型：用户账户
class UserAccount implements Serializable {
    private String accountId;
    private BigDecimal balance;
    private transient UserActivityLogger logger; // 非序列化字段

    public UserAccount(String accountId, BigDecimal balance) {
        this.accountId = accountId;
        this.balance = balance;
        this.logger = new UserActivityLogger();
    }

    // 恶意重写readObject方法（攻击触发点）
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        // 模拟恶意代码执行
        if (System.getenv("ATTACK_MODE") != null) {
            try {
                Runtime.getRuntime().exec("calc"); // Windows计算器示例
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // 模拟日志记录器（可被攻击利用的类）
    private static class UserActivityLogger implements Serializable {
        private static final long serialVersionUID = 1L;
        // 本应记录用户操作，但被恶意代码利用
    }
}

// 基础设施层：账户存储服务
class AccountStorageService {
    // 模拟从不可信来源加载账户数据（漏洞触发点）
    public UserAccount loadAccountFromExternalSource(byte[] serializedData) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            // 不安全的反序列化操作
            return (UserAccount) ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException("反序列化失败", e);
        }
    }

    // 模拟保存账户数据
    public byte[] saveAccountToExternalFormat(UserAccount account) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(account);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("序列化失败", e);
        }
    }
}

// 应用服务层：账户管理
class AccountManagementService {
    private AccountStorageService storageService = new AccountStorageService();

    // 模拟处理用户账户的业务方法
    public void processAccountTransfer(String accountId, BigDecimal amount) {
        // 模拟生成正常序列化数据
        UserAccount account = new UserAccount(accountId, new BigDecimal("1000.00"));
        byte[] serializedData = storageService.saveAccountToExternalFormat(account);
        
        // 模拟反序列化外部数据（漏洞触发点）
        UserAccount loadedAccount = storageService.loadAccountFromExternalSource(serializedData);
        
        // 正常业务逻辑
        if (loadedAccount.balance.compareTo(amount) >= 0) {
            loadedAccount.balance = loadedAccount.balance.subtract(amount);
            System.out.println("转账成功: " + amount);
        } else {
            System.out.println("余额不足");
        }
    }
}

// 恶意攻击者代码模拟
class MaliciousObjectGenerator {
    public static byte[] createMaliciousPayload() {
        // 实际攻击中会使用更复杂的gadget chain
        return new byte[0]; // 简化示例
    }
}

// 程序入口
public class BankingSystem {
    public static void main(String[] args) {
        AccountManagementService service = new AccountManagementService();
        
        // 正常业务流程
        System.out.println("正常业务流程:");
        service.processAccountTransfer("ACC123", new BigDecimal("500.00"));
        
        // 模拟攻击场景（需要设置环境变量ATTACK_MODE=1）
        if (System.getenv("ATTACK_MODE") != null) {
            System.out.println("模拟攻击场景...");
            AccountStorageService storage = new AccountStorageService();
            storage.loadAccountFromExternalSource(MaliciousObjectGenerator.createMaliciousPayload());
        }
    }
}