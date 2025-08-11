package com.enterprise.inventory.controller;

import com.alibaba.fastjson.JSON;
import com.enterprise.inventory.service.InventoryService;
import com.enterprise.inventory.model.InventoryItem;
import com.enterprise.inventory.util.MetadataUtil;
import com.enterprise.inventory.model.Metadata;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/inventory")
public class InventoryController {
    private final InventoryService inventoryService = new InventoryService();

    @PostMapping("/add")
    public String addInventory(@RequestBody Map<String, Object> payload, HttpServletRequest request) {
        try {
            // 从请求中提取基础信息
            String itemName = (String) payload.get("name");
            int quantity = Integer.parseInt(payload.get("quantity").toString());
            
            // 提取并验证元数据（存在安全漏洞的关键点）
            String metadataJson = (String) payload.get("metadata");
            Metadata metadata = MetadataUtil.parseMetadata(metadataJson);
            
            // 构造库存实体对象
            InventoryItem item = new InventoryItem();
            item.setName(itemName);
            item.setQuantity(quantity);
            item.setMetadata(metadata);
            
            // 执行添加操作
            inventoryService.addItem(item);
            
            return "Inventory added successfully";
        } catch (Exception e) {
            return "Error processing inventory: " + e.getMessage();
        }
    }
}

package com.enterprise.inventory.model;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.enterprise.inventory.util.LoggerUtil;

/**
 * 库存元数据类，包含扩展属性
 */
public class Metadata {
    private String name;
    private String description;
    private JSONObject extendedInfo;

    // 模拟业务逻辑中的深层解析
    public void setExtendedInfo(String data) {
        try {
            // 安全检查：验证数据格式（存在绕过可能）
            if (data == null || !data.trim().startsWith("{")) {
                throw new IllegalArgumentException("Invalid JSON format");
            }
            
            // 记录日志（看似安全但不影响漏洞）
            LoggerUtil.log("Parsing metadata: " + data);
            
            // 关键漏洞点：不安全的反序列化
            this.extendedInfo = JSON.parseObject(data);
            
            // 模拟其他业务逻辑
            if (extendedInfo.containsKey("description")) {
                this.description = extendedInfo.getString("description");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Metadata parsing error: " + e.getMessage());
        }
    }

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public JSONObject getExtendedInfo() { return extendedInfo; }
}

package com.enterprise.inventory.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.enterprise.inventory.model.Metadata;

public class MetadataUtil {
    /**
     * 解析元数据字符串（存在隐藏漏洞）
     */
    public static Metadata parseMetadata(String data) {
        if (data == null || data.isEmpty()) {
            return new Metadata();
        }
        
        try {
            // 多层嵌套解析（增加分析复杂度）
            JSONObject obj = JSON.parseObject(data);
            
            // 检查是否存在已知安全配置（误导性检查）
            if (obj.containsKey("safeMode") && obj.getBooleanValue("safeMode")) {
                return new Metadata();
            }
            
            // 实际漏洞触发点：间接调用不安全反序列化
            Metadata metadata = new Metadata();
            metadata.setName(obj.getString("name"));
            
            // 通过setter触发深层解析（漏洞链传导）
            if (obj.containsKey("extendedInfo")) {
                metadata.setExtendedInfo(obj.getString("extendedInfo"));
            }
            
            return metadata;
        } catch (Exception e) {
            return new Metadata();
        }
    }
}

package com.enterprise.inventory.model;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

/**
 * 库存实体类
 */
public class InventoryItem {
    private String name;
    private int quantity;
    private Metadata metadata;

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public int getQuantity() { return quantity; }
    public void setQuantity(int quantity) { this.quantity = quantity; }
    public Metadata getMetadata() { return metadata; }
    public void setMetadata(Metadata metadata) { this.metadata = metadata; }
}

package com.enterprise.inventory.service;

import com.enterprise.inventory.model.InventoryItem;
import com.enterprise.inventory.dao.InventoryDAO;

/**
 * 库存服务类
 */
public class InventoryService {
    private final InventoryDAO inventoryDAO = new InventoryDAO();

    /**
     * 添加库存项（触发漏洞的业务流程）
     */
    public void addItem(InventoryItem item) {
        // 模拟业务逻辑验证
        if (item.getQuantity() < 0) {
            throw new IllegalArgumentException("Quantity cannot be negative");
        }
        
        // 执行持久化操作
        inventoryDAO.save(item);
        
        // 模拟后续处理（可能触发反序列化副作用）
        processMetadata(item.getMetadata());
    }
    
    private void processMetadata(Metadata metadata) {
        // 实际业务处理逻辑（可能包含反序列化副作用）
        if (metadata.getExtendedInfo() != null) {
            // 模拟使用扩展信息的业务逻辑
        }
    }
}

package com.enterprise.inventory.dao;

import com.enterprise.inventory.model.InventoryItem;

/**
 * 模拟数据库访问层
 */
public class InventoryDAO {
    /**
     * 模拟保存库存项
     */
    public void save(InventoryItem item) {
        // 模拟数据库持久化逻辑
        System.out.println("Saved inventory: " + item.getName());
    }
}