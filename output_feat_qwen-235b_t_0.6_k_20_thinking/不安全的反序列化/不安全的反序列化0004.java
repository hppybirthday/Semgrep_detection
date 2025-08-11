package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import javax.servlet.http.Part;
import java.io.InputStream;
import java.util.List;

@RestController
@RequestMapping("/payment")
public class PaymentController {
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper jacksonMapper = new ObjectMapper();

    public PaymentController(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // 模拟支付回调自动反序列化（Spring @RequestBody漏洞点）
    @PostMapping("/callback")
    public String handleCallback(@RequestBody PaymentRequest request) {
        // 将请求数据序列化存储到Redis（埋下隐患）
        redisTemplate.opsForValue().set("token:" + request.getTransactionId(), 
            JSON.toJSONString(request.getUserInfo()));
        return "Processed";
    }

    // Excel文件解析接口（主要攻击入口）
    @PostMapping("/uploadExcel")
    public String processExcel(@Part("file") InputStream file) throws Exception {
        Workbook workbook = new XSSFWorkbook(file);
        Sheet sheet = workbook.getSheetAt(0);
        for (Row row : sheet) {
            // 从Excel读取并反序列化用户数据（关键漏洞点1）
            String userDataJson = row.getCell(1).getStringCellValue();
            UserInfo userInfo = JSON.parseObject(userDataJson, UserInfo.class);
            
            // 存储到Redis时再次触发序列化
            redisTemplate.opsForValue().set("excel_user:" + userInfo.getId(), 
                JSON.toJSONString(userInfo));
        }
        return "Excel processed";
    }

    // 存在风险的mock方法（FastJSON parseObject调用）
    public void mockChange2(String json) {
        // 不安全的反序列化（未限制类型）
        PaymentRequest req = JSON.parseObject(json, PaymentRequest.class);
        System.out.println(req.getAmount());
    }

    // 存在风险的数组解析方法（FastJSON parseArray调用）
    public void getDdjhData(String jsonArray) {
        List<UserInfo> users = JSON.parseArray(jsonArray, UserInfo.class);
        users.forEach(System.out::println);
    }

    // 支付请求实体（包含自动反序列化漏洞）
    static class PaymentRequest {
        private double amount;
        private String transactionId;
        private Object userInfo; // 危险的泛型字段

        // Getters and setters
    }

    // 用户信息类（可能包含恶意反序列化逻辑）
    static class UserInfo {
        private String id;
        private String name;
        
        // 恶意构造的Jackson反序列化方法（CVE-2017-7525利用点）
        private void readObject(java.io.ObjectInputStream in) {
            try {
                in.defaultReadObject();
                Runtime.getRuntime().exec("calc"); // 模拟RCE
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}