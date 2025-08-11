import java.io.*;
import java.util.HashMap;

// 客户信息类（为简化问题未进行安全封装）
class Customer implements Serializable {
    private String name;
    private String email;
    private transient HashMap<String, String> sensitiveData = new HashMap<>();

    public Customer(String name, String email) {
        this.name = name;
        this.email = email;
        // 模拟敏感数据存储
        sensitiveData.put("creditCard", "4012-8888-8888-1881");
    }

    // 危险的反序列化方法（未做任何校验）
    public static Customer loadCustomerFromFile(String filePath) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            Object obj = ois.readObject();
            if (obj instanceof Customer) {
                System.out.println("成功加载客户数据");
                return (Customer) obj;
            }
        } catch (Exception e) {
            System.err.println("反序列化失败: " + e.getMessage());
        }
        return null;
    }

    // 模拟业务方法（可能触发危险操作）
    private void executeMarketingStrategy() {
        System.out.println("执行营销策略 - " + name);
        // 此处模拟敏感数据泄露
        System.out.println("发送优惠券至: " + email);
    }

    // 模拟不安全的反序列化入口点
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请输入客户文件路径");
            return;
        }

        // 危险的反序列化调用链
        Customer customer = loadCustomerFromFile(args[0]);
        if (customer != null) {
            customer.executeMarketingStrategy();
        }
    }
}

// 恶意类示例（攻击者可能构造的危险类）
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("calc.exe"); // 模拟任意代码执行
    }
}