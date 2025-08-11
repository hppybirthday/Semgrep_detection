package com.example.mobileapp.service;

import com.alibaba.fastjson.JSON;
import com.example.mobileapp.dto.DepotCloseRequest;
import com.example.mobileapp.dto.SystemSetting;
import com.example.mobileapp.entity.DepotHead;
import com.example.mobileapp.repository.DepotRepository;
import com.example.mobileapp.utils.JsonUtils;
import com.example.mobileapp.utils.Logger;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class DepotService {
    @Resource
    private DepotRepository depotRepository;

    @Resource
    private AuthService authService;

    /**
     * 批量强制关闭仓库
     * 攻击者可通过构造特殊JSON参数触发反序列化漏洞
     */
    public String forceCloseBatch(String configJson) {
        try {
            // 从配置中提取关键参数
            Map<String, Object> configMap = JsonUtils.jsonToObject(configJson, Map.class);
            
            // 检查认证配置（看似安全的校验逻辑）
            if (!authService.validateAuthConfig(configMap)) {
                return "Auth validation failed";
            }

            // 获取恶意JSON数据（攻击面隐藏在此处）
            Object maliciousData = configMap.get(SystemSetting.AuthProvider.GROUP);
            
            // 危险的反序列化操作（实际漏洞点）
            List<DepotHead> depotList = parseDepotData(maliciousData);
            
            // 执行业务操作（攻击者已通过反序列化获得代码执行）
            for (DepotHead depot : depotList) {
                depot.setStatus("CLOSED");
                depotRepository.save(depot);
            }
            
            return "Depots closed successfully";
            
        } catch (Exception e) {
            Logger.error("Force close batch error: " + e.getMessage());
            return "Operation failed";
        }
    }

    /**
     * 解析仓库数据（隐藏漏洞的间接调用链）
     */
    private List<DepotHead> parseDepotData(Object data) {
        if (data instanceof String) {
            // 存在漏洞的反序列化调用链
            return JsonUtils.jsonToObject((String) data, List.class);
        }
        
        // 安全的类型校验被绕过
        if (data instanceof List<?>) {
            return (List<DepotHead>) data;
        }
        
        return List.of();
    }
}

// FastJSON工具类
package com.example.mobileapp.utils;

import com.alibaba.fastjson.JSON;

public class JsonUtils {
    /**
     * 将JSON字符串转换为目标类型（未做类型白名单校验）
     */
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        try {
            // 存在漏洞的反序列化实现
            return JSON.parseObject(json, clazz);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JSON format");
        }
    }

    /**
     * 通用集合类型反序列化（未限制泛型类型）
     */
    public static <T> T jsonToObject(String json, java.lang.reflect.Type type) {
        try {
            return JSON.parseObject(json, type);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JSON format");
        }
    }
}

// 系统配置类
package com.example.mobileapp.dto;

public class SystemSetting {
    public static class AuthProvider {
        // 攻击者可利用的JSON键
        public static final String GROUP = "group_config";
    }
}

// 恶意请求示例：
// POST /depotHead/forceCloseBatch
// {
//     "group_config": "rO0ABXNyABxjb20uYWxpYmFiYS5mYXN0anNvbi51dGlscy5BZXNDb25maWcAAAAAAAAAAQIAAUwAA2tleXQAEExqYXZhL2xhbmcvU3RyaW5nO3hwAAAA..."
// }
