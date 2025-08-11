import java.io.*;
import java.util.*;
import java.util.function.*;

// 客户信息类（存在可序列化漏洞的载体）
class Customer implements Serializable {
    private String name;
    private transient String creditCard; // 敏感字段

    public Customer(String name, String creditCard) {
        this.name = name;
        this.creditCard = creditCard;
    }

    // 恶意重写readObject方法可导致代码执行
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        System.out.println("[恶意操作] 自动触发信用卡信息泄露: " + creditCard);
    }

    public String toString() {
        return "Customer{name='" + name + "', creditCard='" + creditCard + "'}";
    }
}

// CRM核心处理类
public class CRMSystem {
    // 函数式接口定义反序列化操作
    @FunctionalInterface
    interface DeserializationHandler {
        String handle(byte[] data);
    }

    // 模拟数据库反序列化操作
    public static String unsafeDeserialize(byte[] data, Function<Customer, String> processor) {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // 不安全的反序列化调用（漏洞点）
            Customer customer = (Customer) ois.readObject();
            return processor.apply(customer);
        } catch (Exception e) {
            return "错误: " + e.getMessage();
        }
    }

    public static void main(String[] args) throws IOException {
        // 模拟正常业务流程
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(new Customer("Alice", "4111-1111-1111-1111"));
        }

        // 模拟攻击者篡改数据（实际攻击会构造恶意序列化payload）
        byte[] maliciousData = baos.toByteArray();
        
        // CRM系统正常操作界面
        List<DeserializationHandler> handlers = Arrays.asList(
            data -> unsafeDeserialize(data, c -> "处理客户: " + c.name),
            data -> unsafeDeserialize(data, c -> "显示信用卡: " + c.toString())
        );

        // 模拟用户选择操作
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== CRM系统 ===\
选择操作:\
1. 正常处理\
2. 显示敏感信息");
        int choice = scanner.nextInt();
        
        if (choice >= 1 && choice <= 2) {
            String result = handlers.get(choice-1).apply(maliciousData);
            System.out.println(result);
        } else {
            System.out.println("无效选择");
        }
    }
}