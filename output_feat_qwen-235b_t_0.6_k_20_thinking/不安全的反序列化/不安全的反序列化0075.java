package com.bank.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.util.Map;

// 模拟银行账户服务
public class AccountService {
    private static final ObjectMapper mapper = new ObjectMapper();

    // 元编程风格的动态数据处理
    public void processAccountData(String userData) throws Exception {
        // 模拟从Excel解析的JSON数据
        JSONObject json = JSON.parseObject(userData);
        
        // 危险的双重反序列化操作
        Object rawConfig = json.getObject("config", Object.class);
        ConfigMap config = convertToConfigMap(rawConfig);
        
        // 模拟业务逻辑使用配置
        System.out.println("Processing account: " + config.get("accountId"));
    }

    // 存在漏洞的类型转换方法
    private ConfigMap convertToConfigMap(Object rawConfig) {
        // 反序列化入口点：未验证类型的强制转换
        return JSON.parseObject(JSON.toJSONString(rawConfig), ConfigMap.class);
    }

    // 模拟支付处理的反序列化入口
    public void handlePayment(File paymentData) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(paymentData))) {
            // 直接反序列化不可信数据（真实场景可能来自Excel解析）
            PaymentRequest request = (PaymentRequest) ois.readObject();
            System.out.println("Processing payment: $" + request.getAmount());
        }
    }

    // 可序列化的支付请求类
    public static class PaymentRequest implements java.io.Serializable {
        private String accountId;
        private double amount;
        // getters/setters
    }

    // 动态配置映射类
    public static class ConfigMap extends HashMap<String, Object> {}

    // 模拟Spring控制器
    public static class FileUploadController {
        private final AccountService service = new AccountService();

        public void handleUpload(File file) {
            try {
                // 模拟Excel文件解析流程
                String jsonData = parseExcelToJson(file);
                service.processAccountData(jsonData);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // 模拟存在漏洞的Excel解析器
        private String parseExcelToJson(File excelFile) throws Exception {
            // 这里应有POI解析逻辑，简化为直接读取恶意JSON
            return new String(java.nio.file.Files.readAllBytes(excelFile.toPath()));
        }
    }

    public static void main(String[] args) throws Exception {
        FileUploadController controller = new FileUploadController();
        // 模拟上传包含恶意payload的Excel文件
        controller.handleUpload(new File("malicious_data.json"));
    }
}