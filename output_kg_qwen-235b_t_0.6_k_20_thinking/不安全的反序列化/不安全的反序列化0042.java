package com.crm.example;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

/**
 * CRM客户数据处理控制器
 * 存在不安全反序列化漏洞的示例
 */
@Controller
@RequestMapping("/customer")
public class CustomerController {
    
    /**
     * 模拟客户数据传输对象
     * 实现Serializable接口以支持序列化
     */
    public static class Customer implements Serializable {
        private static final long serialVersionUID = 1L;
        private String name;
        private String email;
        
        public Customer(String name, String email) {
            this.name = name;
            this.email = email;
        }

        public String getName() { return name; }
        public String getEmail() { return email; }
        
        // 恶意代码触发点
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟业务逻辑中的敏感操作
            if("PWNED".equals(name)) {
                Runtime.getRuntime().exec("calc"); // 模拟远程代码执行
            }
        }
    }

    /**
     * 模拟接收序列化数据的接口
     * 存在不安全反序列化漏洞
     */
    @PostMapping("/import")
    @ResponseBody
    public String importCustomer(@RequestParam("data") String base64Data) {
        try {
            byte[] serialized = Base64.getDecoder().decode(base64Data);
            
            // 危险的反序列化操作
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
                Object obj = ois.readObject();
                
                // 类型检查存在绕过可能
                if (obj instanceof Customer) {
                    Customer customer = (Customer) obj;
                    return String.format("成功导入客户: %s <%s>", customer.getName(), customer.getEmail());
                } else {
                    return "数据类型验证失败";
                }
            }
        } catch (Exception e) {
            return "数据导入失败: " + e.getMessage();
        }
    }

    /**
     * 模拟安全的反序列化防护（对比示例）
     * 实际代码中应启用此方法
     */
    private Object safeDeserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais) {
                 @Override
                 protected Class<?> resolveClass(ObjectStreamClass desc) 
                     throws IOException, ClassNotFoundException {
                     // 白名单校验
                     if (!"com.crm.example.CustomerController$Customer".equals(desc.getName())) {
                         throw new InvalidClassException("禁止反序列化非Customer类型: " + desc.getName());
                     }
                     return super.resolveClass(desc);
                 }
             }) {
            return ois.readObject();
        }
    }

    /**
     * 安全版本接口（应启用的防护措施）
     */
    @PostMapping("/safe-import")
    @ResponseBody
    public String safeImportCustomer(@RequestParam("data") String base64Data) {
        try {
            byte[] serialized = Base64.getDecoder().decode(base64Data);
            Object obj = safeDeserialize(serialized);
            
            if (obj instanceof Customer) {
                Customer customer = (Customer) obj;
                return String.format("[安全模式]成功导入客户: %s <%s>", customer.getName(), customer.getEmail());
            } else {
                return "数据类型验证失败";
            }
        } catch (Exception e) {
            return "数据导入失败: " + e.getMessage();
        }
    }
}