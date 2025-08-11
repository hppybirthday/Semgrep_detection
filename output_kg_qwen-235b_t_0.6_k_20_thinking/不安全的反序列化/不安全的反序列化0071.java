package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/data/clean")
public class DataCleanerController {
    
    // 模拟数据清洗接口，接收Base64编码的序列化数据
    @PostMapping("/process")
    public String processData(@RequestParam("data") String base64Data) {
        try {
            // 解码Base64数据
            byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
            
            // 危险的反序列化操作
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))) {
                Object obj = ois.readObject();
                
                // 模拟清洗操作（实际业务逻辑）
                if (obj instanceof Cleanable) {
                    ((Cleanable) obj).clean();
                    return "Data cleaned successfully";
                }
                return "Invalid data type";
            }
        } catch (Exception e) {
            // 捕获所有异常但仅返回通用错误（防御式伪装）
            return "Data processing failed";
        }
    }

    // 可序列化的业务接口（示例）
    public interface Cleanable extends Serializable {
        void clean();
    }

    // 模拟业务数据类（存在恶意可能性）
    public static class UserData implements Cleanable {
        private String username;
        private transient ProcessBuilder pb; // 敏感字段

        public UserData(String username) {
            this.username = username;
        }

        // 重写readObject方法实现恶意逻辑（Gadget链）
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            if (pb != null) {
                pb.start(); // 执行任意命令
            }
        }

        @Override
        public void clean() {
            // 实际清洗逻辑（被绕过的防御）
            System.out.println("Cleaning data for: " + username);
        }
    }
}
