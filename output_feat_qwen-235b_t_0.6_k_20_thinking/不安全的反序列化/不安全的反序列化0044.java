package com.crm.example.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
    // 模拟CRM系统客户数据处理
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            Workbook workbook = new XSSFWorkbook(file.getInputStream());
            Sheet sheet = workbook.getSheetAt(0);
            
            // 遍历Excel行数据
            for (Row row : sheet) {
                Cell jsonCell = row.getCell(2); // 第三列存储JSON扩展字段
                if (jsonCell != null) {
                    String jsonData = jsonCell.getStringCellValue();
                    // 危险的反序列化操作
                    JSONObject obj = JSON.parseObject(jsonData);
                    mockChange2(obj);
                }
            }
            return "Data processed successfully";
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }

    // 存在漏洞的反序列化方法
    private void mockChange2(JSONObject input) {
        // 未进行类型检查，直接反序列化为任意对象
        Object customer = JSON.parseObject(input.toJSONString(), Object.class);
        System.out.println("Processing customer: " + customer);
    }

    // 另一个反序列化入口点
    @GetMapping("/data")
    public List<Customer> getDdjhData(@RequestParam String data) {
        // 不安全的JSON数组解析
        return JSON.parseArray(data, Customer.class);
    }

    // Spring自动反序列化入口点
    @PostMapping("/save")
    public String saveCustomer(@RequestBody Customer customer) {
        // 业务逻辑处理
        return "Customer saved: " + customer.getName();
    }

    // 客户数据实体类
    public static class Customer {
        private String name;
        private String phone;
        private String address;
        
        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getPhone() { return phone; }
        public void setPhone(String phone) { this.phone = phone; }
        public String getAddress() { return address; }
        public void setAddress(String address) { this.address = address; }
    }
}