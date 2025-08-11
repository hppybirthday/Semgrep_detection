package com.crm.example;

import java.io.*;
import java.util.Base64;
import java.util.function.Function;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/customers")
public class CustomerController {

    // 敏感类：客户信息
    public static class Customer implements Serializable {
        private String name;
        private transient String secretKey; // 敏感字段
        
        public Customer(String name) {
            this.name = name;
            this.secretKey = "INTERNAL_API_KEY_12345";
        }
        
        // 恶意逻辑：反序列化时自动执行
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            try {
                // 模拟敏感信息泄露
                Runtime.getRuntime().exec("echo Leaked secret: " + secretKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // 函数式处理链
    private final Function<byte[], Object> deserializer = bytes -> {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException("Deserialization failed", e);
        }
    };

    // 漏洞入口点
    @PostMapping("/import")
    public String importCustomers(@RequestParam("data") String base64Data, HttpServletRequest request) {
        try {
            // 危险操作：直接反序列化用户输入
            byte[] data = Base64.getDecoder().decode(base64Data);
            
            // 模拟审计日志记录（未记录敏感数据）
            System.out.println("[" + request.getRemoteAddr() + "] Importing customers...");
            
            // 函数式调用链
            Object obj = deserializer.apply(data);
            
            // 验证逻辑缺失
            if (obj instanceof Customer) {
                return "Import successful";
            }
            return "Invalid data format";
        } catch (Exception e) {
            return "Import failed: " + e.getMessage();
        }
    }

    // 漏洞利用示例（攻击者视角）
    public static void main(String[] args) throws Exception {
        // 构造恶意序列化数据
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(new Customer("MaliciousUser"));
        }
        
        // 模拟攻击请求
        String payload = Base64.getEncoder().encodeToString(bos.toByteArray());
        System.out.println("Attack payload: " + payload);
        // 实际攻击中可通过curl等工具发送请求
        // curl -X POST "http://crm.example.com/customers/import?data="+payload
    }
}