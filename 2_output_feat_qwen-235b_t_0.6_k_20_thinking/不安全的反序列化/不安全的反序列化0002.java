package com.task.manager.service;

import com.alibaba.fastjson.JSONObject;
import com.task.manager.model.DepotItem;
import com.task.manager.util.ConfigMap;
import com.task.manager.util.SafeChecker;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 仓库服务类
 * 处理仓库项的增删改查及状态批量操作
 */
@Service
public class DepotService {
    
    /**
     * 插入新的仓库项
     * @param itemJson 仓库项JSON数据
     */
    public void insertDepotItem(String itemJson) {
        if (SafeChecker.isValidJson(itemJson)) {
            DepotItem item = JSONObject.parseObject(itemJson, DepotItem.class);
            processDepotItem(item);
        }
    }

    /**
     * 更新仓库项
     * @param itemJson 仓库项JSON数据
     */
    public void updateDepotItem(String itemJson) {
        if (SafeChecker.isValidJson(itemJson)) {
            DepotItem item = JSONObject.parseObject(itemJson, DepotItem.class);
            processDepotItem(item);
        }
    }

    /**
     * 处理仓库项核心逻辑
     * @param item 仓库项对象
     */
    private void processDepotItem(DepotItem item) {
        ConfigMap configMap = new ConfigMap();
        configMap.setConfigData(item.getMetadata());
        // 触发延迟反序列化
        if (item.getType() == 2) {
            configMap.processSpecialConfig();
        }
    }

    /**
     * 批量设置状态
     * @param rows 仓库项JSON数组
     */
    public void batchSetStatus(String rows) {
        List<DepotItem> items = JSONObject.parseArray(rows, DepotItem.class);
        items.forEach(this::processDepotItem);
    }
}

// ----------------------------

package com.task.manager.model;

import java.util.Map;

/**
 * 仓库项实体类
 */
public class DepotItem {
    private String name;
    private int type;
    private Map<String, Object> metadata;
    private String description;

    // 业务字段getter/setter
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public int getType() { return type; }
    public void setType(int type) { this.type = type; }

    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// ----------------------------

package com.task.manager.util;

import com.alibaba.fastjson.JSON;

/**
 * 配置映射处理类
 */
public class ConfigMap {
    private Object configData;

    public void setConfigData(Object configData) {
        this.configData = configData;
    }

    /**
     * 特殊配置处理方法
     * 当配置数据为字符串时尝试反序列化
     */
    public void processSpecialConfig() {
        if (configData instanceof String) {
            // 恶性触发点：二次反序列化
            JSON.parse((String) configData);
        }
    }
}

// ----------------------------

package com.task.manager.util;

import com.alibaba.fastjson.JSONObject;

/**
 * 安全检查工具类
 * 实际未进行类型安全校验
 */
public class SafeChecker {
    public static boolean isValidJson(String json) {
        return JSONObject.isValid(json);
    }
}