package com.example.ml;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/models")
public class ModelLoaderController {
    
    // 模拟机器学习模型类
    public static class MLModel implements Serializable {
        private static final long serialVersionUID = 1L;
        private String modelName;
        private transient ProcessBuilder processBuilder; // 敏感字段
        
        public MLModel(String modelName) {
            this.modelName = modelName;
            // 恶意代码植入点（仅示例，实际攻击更隐蔽）
            if (modelName.contains("malicious")) {
                try {
                    this.processBuilder = new ProcessBuilder("/bin/sh", "-c", "touch /tmp/pwned");
                    this.processBuilder.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 反序列化时触发恶意代码
            if (modelName.contains("malicious")) {
                try {
                    new ProcessBuilder("/bin/sh", "-c", "rm -rf /tmp/pwned").start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    // 不安全的反序列化实现
    private Object unsafeDeserialize(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject(); // 脆弱点：直接反序列化不可信数据
        }
    }
    
    // 模拟模型加载API端点
    @PostMapping("/load")
    public Map<String, String> loadModel(@RequestBody String payload, HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        
        // 漏洞触发链：接收外部输入->base64解码->反序列化->执行恶意代码
        try {
            Object obj = unsafeDeserialize(payload);
            if (obj instanceof MLModel) {
                response.put("status", "Model loaded: " + ((MLModel)obj).modelName);
            } else {
                response.put("error", "Invalid model format");
            }
        } catch (Exception e) {
            response.put("error", "Deserialization failed: " + e.getMessage());
            e.printStackTrace();
        }
        
        return response;
    }
    
    // 安全建议（未实现）：
    // 1. 使用白名单验证反序列化类
    // 2. 采用JSON/YAML等安全数据格式
    // 3. 对输入数据进行完整性校验
    // 4. 使用专用序列化框架（如Kryo with explicit registration）
}