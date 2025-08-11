package com.example.bank.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.InputStream;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/config")
public class RiskyConfigController {
    
    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public @ResponseBody String uploadConfig(@RequestParam("file") MultipartFile file) {
        try {
            InputStream inputStream = file.getInputStream();
            Workbook workbook = new XSSFWorkbook(inputStream);
            Sheet sheet = workbook.getSheetAt(0);
            Row row = sheet.getRow(1);
            Cell configCell = row.getCell(0);
            
            // 模拟从Excel读取JSON配置字符串
            String rawJson = configCell.getStringCellValue();
            
            // 不安全的反序列化过程
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY);
            
            // 漏洞点1: 使用readTree解析不受信任的JSON
            JsonNode rootNode = mapper.readTree(rawJson);
            
            // 漏洞点2: 无类型限制的convertValue调用
            Map<String, Object> configMap = mapper.convertValue(rootNode, Map.class);
            
            // 模拟处理配置数据（实际可能触发恶意代码）
            processConfig(configMap);
            
            return "Configuration processed successfully";
        } catch (Exception e) {
            return "Error processing configuration: " + e.getMessage();
        }
    }
    
    private void processConfig(Map<String, Object> config) {
        // 模拟后续处理逻辑
        // 可能存在的深层访问触发反序列化漏洞
        if (config.containsKey("hooks")) {
            Object hook = config.get("hooks");
            // 危险操作：可能触发恶意代码执行
            hook.toString(); // 模拟触发getter方法调用
        }
    }
    
    // 模拟银行配置数据结构
    public static class BankConfig {
        public String configName;
        public int version;
        public Map<String, Object> metadata;
    }
}