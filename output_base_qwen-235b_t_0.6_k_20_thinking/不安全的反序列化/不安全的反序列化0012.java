import java.io.*;
import java.util.*;
import java.util.function.*;
import java.nio.file.*;

// 客户信息类（存在可序列化风险）
class Customer implements Serializable {
    private String name;
    private String email;
    private transient String sensitiveData; // 敏感字段本应加密存储
    
    public Customer(String name, String email) {
        this.name = name;
        this.email = email;
        this.sensitiveData = "CREDIT_CARD:1234-5678-9012-3456";
    }
    
    // 使用函数式接口实现数据校验
    public static Function<Customer, Boolean> validate = c -> 
        c.name != null && c.email.contains("@");
    
    @Override
    public String toString() {
        return String.format("Customer{name='%s', email='%s'}", name, email);
    }
}

// CRM核心服务类
class CRMService {
    // 函数式接口定义反序列化操作
    public static Function<String, Customer> loadCustomer = filePath -> {
        try (ObjectInputStream ois = new ObjectInputStream(
             new FileInputStream(filePath))) {
            // 不安全的反序列化操作
            return (Customer) ois.readObject();
        } catch (Exception e) {
            System.err.println("Deserialization failed: " + e.getMessage());
            return null;
        }
    };
    
    // 模拟数据持久化存储
    public static Consumer<Customer> saveCustomer = customer -> {
        try (ObjectOutputStream oos = new ObjectOutputStream(
             new FileOutputStream("customer.dat"))) {
            oos.writeObject(customer);
        } catch (Exception e) {
            System.err.println("Serialization failed: " + e.getMessage());
        }
    };
}

public class UnsafeDeserializationDemo {
    public static void main(String[] args) {
        // 正常业务流程
        Customer customer = new Customer("John Doe", "john@example.com");
        CRMService.saveCustomer.accept(customer);
        
        // 模拟攻击场景
        if (args.length > 0 && args[0].equals("--malicious")) {
            try {
                // 攻击者篡改序列化文件
                Files.write(Paths.get("customer.dat"), 
                    Base64.getDecoder().decode("rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnH1fUBAAB4cHwAAAAA"));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        // 危险的反序列化操作
        Customer loaded = CRMService.loadCustomer.apply("customer.dat");
        if (loaded != null) {
            System.out.println("Loaded customer: " + loaded);
            // 触发敏感数据泄露
            System.out.println("Sensitive data: " + loaded.toString());
        }
    }
}