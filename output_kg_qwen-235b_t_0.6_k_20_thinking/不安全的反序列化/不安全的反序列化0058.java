package com.crm.example;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * CRM系统中的客户信息反序列化服务
 */
public class CustomerDeserializer {
    
    // 模拟CRM系统中客户实体类
    public static class Customer implements Serializable {
        private String name;
        private transient String sensitiveData; // 敏感字段
        
        public Customer(String name) {
            this.name = name;
            this.sensitiveData = "INTERNAL_SSO_TOKEN";
        }

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟敏感数据初始化
            sensitiveData = "RECONSTRUCTED_TOKEN";
        }
    }

    // 模拟反序列化服务
    public static class DeserializationService {
        public Object unsafeDeserialize(String base64Data) throws Exception {
            // 漏洞点：直接反序列化不可信数据
            byte[] data = Base64.getDecoder().decode(base64Data);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                return ois.readObject(); // 危险的反序列化操作
            }
        }
    }

    // 模拟Web层接口
    public static class CustomerController {
        private DeserializationService deserializer = new DeserializationService();

        public String handleDeserializationRequest(String payload) {
            try {
                // 模拟处理客户端提交的序列化数据
                Object obj = deserializer.unsafeDeserialize(payload);
                
                if (obj instanceof Customer) {
                    Customer customer = (Customer) obj;
                    return String.format("Successfully deserialized customer: %s", customer.name);
                }
                return "Invalid object type";
            } catch (Exception e) {
                return String.format("Deserialization error: %s", e.getMessage());
            }
        }
    }

    // 模拟攻击者利用链
    public static class AttackGadget implements Serializable {
        private String command;
        
        public AttackGadget(String cmd) {
            this.command = cmd;
        }

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟执行任意命令（实际需要结合具体gadget链）
            Runtime.getRuntime().exec(command); // 漏洞触发点
        }
    }

    // 模拟主程序
    public static void main(String[] args) {
        CustomerController controller = new CustomerController();
        
        // 正常业务场景：序列化客户数据
        Customer normalCustomer = new Customer("John Doe");
        String serialized = serializeObject(normalCustomer);
        System.out.println("Normal usage:");
        System.out.println(controller.handleDeserializationRequest(serialized));
        
        // 恶意攻击演示（需要实际gadget链支持）
        System.out.println("\
Malicious attack simulation:");
        if (args.length > 0 && args[0].equals("--exploit")) {
            try {
                String maliciousPayload = serializeObject(new AttackGadget("calc"));
                controller.handleDeserializationRequest(maliciousPayload);
            } catch (Exception e) {
                System.err.println("Exploit failed: " + e.getMessage());
            }
        }
    }

    // 辅助方法：对象序列化
    private static String serializeObject(Serializable obj) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(obj);
            oos.flush();
            oos.close();
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Serialization error: " + e.getMessage());
        }
    }
}