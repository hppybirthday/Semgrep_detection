import java.io.*;
import java.lang.reflect.Method;
import java.util.Base64;

// 模拟银行用户类
class BankUser implements Serializable {
    private String username;
    private double balance;
    
    public BankUser(String username, double balance) {
        this.username = username;
        this.balance = balance;
    }
    
    // 敏感操作：转账方法
    public void transfer(BankUser target, double amount) {
        if(this.balance >= amount) {
            this.balance -= amount;
            target.balance += amount;
            System.out.println("[TRANSFER] " + amount + " from " + this.username + " to " + target.username);
        }
    }
    
    @Override
    public String toString() {
        return "User: " + username + " | Balance: $" + balance;
    }
}

// 元编程风格的反序列化处理器
class UnsafeDeserializer {
    public static Object deserialize(byte[] data) throws Exception {
        // 使用反射动态创建ObjectInputStream
        Class<?> clazz = Class.forName("java.io.ObjectInputStream");
        Method constructor = clazz.getDeclaredMethod("<init>", InputStream.class);
        constructor.setAccessible(true);
        Object ois = constructor.invoke(null, new ByteArrayInputStream(data));
        
        // 动态调用readObject方法
        Method readMethod = clazz.getMethod("readObject");
        return readMethod.invoke(ois);
    }
}

public class BankingSystem {
    public static void main(String[] args) {
        try {
            // 模拟正常序列化流程
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            BankUser user = new BankUser("Alice", 1000000.0);
            oos.writeObject(user);
            oos.close();
            
            // 恶意输入：攻击者构造的反序列化payload（模拟网络传输）
            String maliciousInput = "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eLndSTmZ8AADWgAFbW9kaWZpZWR0ABJMamF2YS91dGlsL0FycmF5TGlzdDt4cHcEAAAAfHg=";
            byte[] data = Base64.getDecoder().decode(maliciousInput);
            
            // 不安全的反序列化调用
            Object obj = UnsafeDeserializer.deserialize(data);
            System.out.println("Deserialized: " + obj);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}