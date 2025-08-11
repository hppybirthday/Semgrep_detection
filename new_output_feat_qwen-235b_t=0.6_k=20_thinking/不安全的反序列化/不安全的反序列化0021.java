package com.bankcore.financial;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.poi.ss.usermodel.*;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Iterator;

/**
 * 资源管理服务，处理Excel文件上传及缓存操作
 * @author bankcore
 */
@Service
public class ResourceService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 添加资源（处理Excel上传）
     */
    public String addResource(byte[] excelData) {
        try {
            Workbook workbook = WorkbookFactory.create(new ByteArrayInputStream(excelData));
            Sheet sheet = workbook.getSheetAt(0);
            Iterator<Row> rowIterator = sheet.iterator();
            
            while (rowIterator.hasNext()) {
                Row row = rowIterator.next();
                if (row.getRowNum() == 0) continue; // 跳过标题行
                
                String configJson = row.getCell(2).getStringCellValue();
                processConfig(configJson); // 漏洞触发点
            }
            return "资源添加成功";
        } catch (Exception e) {
            return "处理失败: " + e.getMessage();
        }
    }
    
    /**
     * 更新资源配置
     */
    public void updateResource(String resourceId, JSONObject config) {
        String cacheKey = "RESOURCE_" + resourceId;
        redisTemplate.opsForValue().set(cacheKey, config); // 使用默认Java序列化
    }
    
    /**
     * 处理配置JSON字符串
     */
    private void processConfig(String configJson) {
        JSONObject configObj = JSON.parseObject(configJson);
        if (configObj.containsKey("authProvider")) {
            String providerType = configObj.getString("authProvider");
            if ("GROUP".equals(providerType)) {
                // 危险的反序列化操作
                Object authConfig = JSON.parseObject(
                    configJson,
                    getAuthConfigClass(providerType)
                );
                validateAuthConfig(authConfig);
            }
        }
    }
    
    /**
     * 获取认证配置类类型（存在逻辑误导）
     */
    private Class<?> getAuthConfigClass(String providerType) {
        try {
            // 潜在的类加载漏洞
            return Class.forName("com.bankcore.auth." + providerType + "AuthProvider");
        } catch (ClassNotFoundException e) {
            return DefaultAuthProvider.class;
        }
    }
    
    /**
     * 验证认证配置（空实现造成漏洞掩盖）
     */
    private void validateAuthConfig(Object config) {
        // 本应进行安全校验，实际未实现
    }
    
    /**
     * 从Redis获取资源配置（二次漏洞触发点）
     */
    public JSONObject getCachedResource(String resourceId) {
        String cacheKey = "RESOURCE_" + resourceId;
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        if (cached instanceof JSONObject) {
            return (JSONObject) cached;
        }
        return new JSONObject();
    }
}

/**
 * 默认认证提供者（可被攻击利用的Gadget类）
 */
class DefaultAuthProvider implements java.io.Serializable {
    private String command;
    
    public void setCommand(String cmd) {
        this.command = cmd;
    }
    
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (command != null) {
            try {
                // 模拟危险操作（真实场景可能调用Runtime.exec）
                System.out.println("执行命令: " + command);
            } catch (Exception e) {
                // 忽略异常
            }
        }
    }
}