package com.example.vulnerableapp;

import com.alibaba.fastjson.JSON;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/data-clean")
public class DataCleaningController {
    
    // 模拟数据清洗接口，接收Excel文件上传
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            InputStream inputStream = file.getInputStream();
            Workbook workbook = new XSSFWorkbook(inputStream);
            Sheet sheet = workbook.getSheetAt(0);
            
            List<CleanedData> result = new ArrayList<>();
            
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // 跳过表头
                
                // 假设Excel包含三列：ID, NAME, JSON_EXTRA_INFO
                String id = row.getCell(0).getStringCellValue();
                String name = row.getCell(1).getStringCellValue();
                String jsonExtraInfo = row.getCell(2).getStringCellValue();
                
                // 调用存在漏洞的反序列化方法
                List<String> extraInfo = getDdjhData(jsonExtraInfo);
                
                // 模拟数据清洗逻辑
                CleanedData cleaned = new CleanedData();
                cleaned.setId(id.trim());
                cleaned.setName(name.toUpperCase());
                cleaned.setTags(extraInfo);
                
                result.add(cleaned);
            }
            
            return "Processed " + result.size() + " records";
            
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }
    
    // 存在漏洞的反序列化方法
    private List<String> getDdjhData(String jsonData) {
        // 错误使用fastjson反序列化任意JSON数组到String列表
        // 未指定类型限制，未开启安全模式
        // 攻击者可构造恶意JSON触发JNDI注入
        return JSON.parseArray(jsonData, String.class); // VULNERABLE LINE
    }
    
    // 模拟数据模型类
    static class CleanedData {
        private String id;
        private String name;
        private List<String> tags;
        
        // Getters and setters
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public List<String> getTags() { return tags; }
        public void setTags(List<String> tags) { this.tags = tags; }
    }
}