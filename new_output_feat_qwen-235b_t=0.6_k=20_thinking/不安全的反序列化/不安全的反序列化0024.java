package com.mobile.app.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 处理移动客户端上传的配置文件
 */
@Service
public class MobileConfigService {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 处理上传的Excel配置文件
     */
    public String processConfigFile(MultipartFile file) throws IOException {
        try (Workbook workbook = new XSSFWorkbook(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0);
            
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // 跳过表头
                
                Cell roleCell = row.getCell(0);
                Cell depCell = row.getCell(1);
                
                String role = roleCell.getStringCellValue();
                String dependencies = depCell.getStringCellValue();
                
                // 验证依赖配置格式
                if (!validateRoleDependencies(dependencies)) {
                    throw new IllegalArgumentException("Invalid role dependencies format");
                }
                
                // 存储到Redis
                redisTemplate.opsForHash().put("role_config", role, dependencies);
            }
            
            // 更新系统配置
            updateRoleConfigs();
            return "Configuration updated successfully";
        }
    }
    
    /**
     * 验证角色依赖格式（表面验证）
     */
    private boolean validateRoleDependencies(String json) {
        try {
            JSONObject.parseObject(json);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 从Redis加载并更新角色配置
     */
    private void updateRoleConfigs() {
        Map<String, Object> rawConfigs = redisTemplate.opsForHash().entries("role_config");
        Map<String, RoleDependencies> configs = new HashMap<>();
        
        for (Map.Entry<String, Object> entry : rawConfigs.entrySet()) {
            String role = entry.getKey();
            String json = (String) entry.getValue();
            
            // 漏洞点：不安全的反序列化
            configs.put(role, JSON.parseObject(json, RoleDependencies.class));
        }
        
        // 缓存到本地
        RoleConfigCache.getInstance().updateConfigs(configs);
    }
}

/**
 * 角色依赖关系实体类
 */
class RoleDependencies {
    private Map<String, String> permissions = new HashMap<>();
    private String auditLevel;
    
    // FastJSON反序列化利用链入口点
    public void setPermissions(Map<String, String> permissions) {
        this.permissions = permissions;
    }
    
    public void setAuditLevel(String auditLevel) {
        this.auditLevel = auditLevel;
    }
}

/**
 * 角色配置本地缓存
 */
class RoleConfigCache {
    private static final RoleConfigCache INSTANCE = new RoleConfigCache();
    private Map<String, RoleDependencies> configs = new HashMap<>();
    
    private RoleConfigCache() {}
    
    public static RoleConfigCache getInstance() {
        return INSTANCE;
    }
    
    public void updateConfigs(Map<String, RoleDependencies> newConfigs) {
        configs.clear();
        configs.putAll(newConfigs);
    }
    
    public RoleDependencies getConfig(String role) {
        return configs.get(role);
    }
}