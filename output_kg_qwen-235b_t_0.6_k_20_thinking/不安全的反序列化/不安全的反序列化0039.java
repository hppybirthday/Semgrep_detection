package com.example.bigdata;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.*;

/**
 * 大数据处理服务控制器
 * 存在不安全的反序列化漏洞
 */
@RestController
@RequestMapping("/data")
public class DataProcessingController {
    
    /**
     * 模拟大数据任务配置类
     * 可序列化对象，存在潜在攻击面
     */
    private static class TaskConfig implements Serializable {
        private String jobName;
        private int priority;
        private Map<String, Object> parameters = new HashMap<>();
        
        public TaskConfig(String jobName, int priority) {
            this.jobName = jobName;
            this.priority = priority;
        }
        
        @Override
        public String toString() {
            return "TaskConfig[" + jobName + ", priority=" + priority + "]";
        }
    }
    
    /**
     * 恶意反序列化端点
     * 直接处理Base64编码的序列化对象
     * @param payload - Base64编码的序列化数据
     * @return 处理结果
     */
    @PostMapping("/process")
    public String processSerializedData(@RequestParam("data") String payload) {
        try {
            // 漏洞点：直接反序列化不可信数据
            byte[] decoded = Base64.getDecoder().decode(payload);
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 危险操作：直接读取对象
            Object obj = ois.readObject();
            ois.close();
            
            // 潜在利用点：如果对象包含恶意代码
            if (obj instanceof TaskConfig) {
                return "Processed valid task: " + obj.toString();
            }
            return "Processed unknown object: " + obj.getClass().getName();
            
        } catch (Exception e) {
            return "Error processing data: " + e.getMessage();
        }
    }
    
    /**
     * 安全版本示例（注释掉的修复方案）
     */
    /*
    private Object safeDeserialize(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) 
                throws IOException, ClassNotFoundException {
                // 白名单验证
                if (!desc.getName().equals(TaskConfig.class.getName())) {
                    throw new InvalidClassException("Unauthorized deserialization", desc.getName());
                }
                return super.resolveClass(desc);
            }
        };
        return ois.readObject();
    }
    */
    
    /**
     * 测试数据生成端点（用于演示）
     */
    @GetMapping("/generate")
    public String generateSample() throws Exception {
        TaskConfig config = new TaskConfig("testJob", 5);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(config);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}