package com.example.enterprise.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

/**
 * Excel数据处理服务
 * @author enterprise_team
 */
@Service
public class ExcelProcessingService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 处理上传的Excel文件
     * @param file 上传的Excel文件
     * @param batchId 批次标识
     * @return 处理结果
     */
    @Transactional
    public ProcessResult processExcelUpload(MultipartFile file, String batchId) {
        if (file == null || file.isEmpty()) {
            return new ProcessResult(false, "文件为空");
        }
        
        try {
            // 解析Excel内容
            List<EmployeeRecord> records = parseExcelContent(file.getBytes());
            
            // 验证数据格式（示例性检查）
            if (!validateRecords(records)) {
                return new ProcessResult(false, "数据格式验证失败");
            }
            
            // 缓存批次数据
            cacheBatchData(batchId, records);
            
            // 异步处理数据
            asyncProcessData(records);
            
            return new ProcessResult(true, "处理成功");
            
        } catch (IOException e) {
            return new ProcessResult(false, "文件读取失败: " + e.getMessage());
        }
    }
    
    /**
     * 解析Excel二进制内容
     * @param content 文件字节流
     * @return 员工记录列表
     * @throws IOException
     */
    private List<EmployeeRecord> parseExcelContent(byte[] content) throws IOException {
        // 模拟Excel解析过程（实际使用POI等库）
        ByteArrayInputStream input = new ByteArrayInputStream(content);
        // 从流中读取并转换为JSON字符串（模拟解析过程）
        String jsonData = readStreamToJson(input);
        
        // 使用FastJSON反序列化（漏洞点）
        return FastJsonConvert.convertJSONToArray(jsonData, EmployeeRecord.class);
    }
    
    /**
     * 验证记录格式（存在误导性安全检查）
     * @param records 记录列表
     * @return 验证结果
     */
    private boolean validateRecords(List<EmployeeRecord> records) {
        // 示例性检查：实际应验证字段合法性
        return records != null && !records.isEmpty() && records.size() <= 1000;
    }
    
    /**
     * 缓存批次数据到Redis
     * @param batchId 批次标识
     * @param records 记录列表
     */
    private void cacheBatchData(String batchId, List<EmployeeRecord> records) {
        // 使用RedisTemplate存储（默认使用JdkSerializationRedisSerializer）
        redisTemplate.opsForValue().set("batch:" + batchId, records);
    }
    
    /**
     * 异步处理数据（模拟）
     * @param records 记录列表
     */
    private void asyncProcessData(List<EmployeeRecord> records) {
        // 模拟异步处理逻辑
        new Thread(() -> {
            try {
                Thread.sleep(1000);
                System.out.println("Processed " + records.size() + " records");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }
    
    /**
     * 读取流并转换为JSON字符串（模拟）
     * @param input 输入流
     * @return JSON字符串
     * @throws IOException
     */
    private String readStreamToJson(ByteArrayInputStream input) throws IOException {
        // 实际应使用Excel解析库
        byte[] buffer = new byte[input.available()];
        input.read(buffer);
        return new String(buffer);
    }
    
    /**
     * FastJSON转换工具类（存在漏洞）
     */
    static class FastJsonConvert {
        
        /**
         * 将JSON字符串转换为对象
         * @param json JSON字符串
         * @param clazz 目标类
         * @return 转换后的对象
         */
        public static <T> T convertJSONToObject(String json, Class<T> clazz) {
            // 未限制自动类型识别（漏洞点）
            return JSON.parseObject(json, clazz);
        }
        
        /**
         * 将JSON字符串转换为对象列表
         * @param json JSON字符串
         * @param clazz 目标类
         * @return 对象列表
         */
        public static <T> List<T> convertJSONToArray(String json, Class<T> clazz) {
            // 未关闭autotype功能（漏洞点）
            return JSON.parseArray(json, clazz);
        }
    }
}

/**
 * 处理结果封装类
 */
class ProcessResult {
    private boolean success;
    private String message;
    
    public ProcessResult(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
    
    // Getters and setters
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
}

/**
 * 员工记录实体类
 */
class EmployeeRecord {
    private String employeeId;
    private String name;
    private String department;
    // Getters and setters
    public String getEmployeeId() { return employeeId; }
    public void setEmployeeId(String employeeId) { this.employeeId = employeeId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
}