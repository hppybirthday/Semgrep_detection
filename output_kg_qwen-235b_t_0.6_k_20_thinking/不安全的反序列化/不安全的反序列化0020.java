package com.example.demo;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    
    @PostMapping("/deserialize")
    public String unsafeDeserialization(@RequestParam String data) {
        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();
            return "Deserialized: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟业务实体类
    public static class User implements Serializable {
        private String username;
        private transient String password; // 敏感字段
        
        // 模拟需要执行的危险操作
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            if (username != null && username.contains("malicious")) {
                Runtime.getRuntime().exec("calc"); // 模拟RCE
            }
        }
    }

    // 模拟另一个可序列化类
    public static class Order implements Serializable {
        private String orderId;
        private double amount;
    }

    // 漏洞利用示例：
    // curl -X POST "http://localhost:8080/api/deserialize?data=$(java -jar ysoserial.jar CommonsCollections5 'calc')"
}

/*
攻击面分析：
1. 全开放的反序列化入口：任何实现Serializable接口的类都可以被反序列化
2. 未进行类型检查：允许反序列化任意类实例
3. 未过滤危险类：未阻止包含危险readObject方法的类
4. 未使用安全反序列化库：直接使用基础ObjectInputStream

漏洞原理：
Java反序列化过程中会调用对象的readObject方法，攻击者可以通过构造特殊的序列化链，
在反序列化时触发任意代码执行。常见利用链如CommonsCollections的Transformer链，
可以构造出无需交互的远程代码执行漏洞。
*/