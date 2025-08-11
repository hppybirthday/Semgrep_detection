import java.io.*;
import java.util.*;

// 客户信息类（存在可序列化漏洞）
class Customer implements Serializable {
    private String name;
    private String email;
    private transient String password; // 敏感字段

    public Customer(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }

    // 模拟业务逻辑方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        System.out.println("[调试] 加载客户数据: " + this);
    }
}

// 数据处理工具类
class DataProcessor {
    // 不安全的反序列化操作
    public static Object loadFromFile(String filename) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            return ois.readObject(); // 危险的反序列化
        }
    }

    public static void saveToFile(String filename, Object obj) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(obj);
        }
    }
}

// 主程序类
public class CRMSystem {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\
=== CRM系统 ===");
            System.out.println("1. 导出客户数据");
            System.out.println("2. 导入客户数据");
            System.out.println("3. 退出");
            System.out.print("请选择操作: ");

            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    try {
                        Customer customer = new Customer("test","test@example.com","secret123");
                        DataProcessor.saveToFile("customer.ser", customer);
                        System.out.println("数据导出成功");
                    } catch (IOException e) {
                        System.out.println("导出失败: " + e.getMessage());
                    }
                    break;
                case "2":
                    try {
                        Object obj = DataProcessor.loadFromFile("customer.ser");
                        if (obj instanceof Customer) {
                            System.out.println("导入成功: " + obj);
                        }
                    } catch (Exception e) {
                        System.out.println("导入失败: " + e.getMessage());
                    }
                    break;
                case "3":
                    System.out.println("再见！");
                    return;
                default:
                    System.out.println("无效选项");
            }
        }
    }
}