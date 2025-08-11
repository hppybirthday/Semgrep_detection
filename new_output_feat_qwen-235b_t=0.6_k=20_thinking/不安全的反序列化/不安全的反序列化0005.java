package com.iot.device.controller;

import com.alibaba.fastjson.JSONObject;
import com.iot.device.service.DeviceService;
import com.iot.device.util.CommandValidator;
import com.iot.device.entity.DeviceCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * IoT设备控制中心
 * 处理智能设备状态更新与指令下发
 */
@RestController
@RequestMapping("/device")
public class DeviceController {
    private static final Logger logger = LoggerFactory.getLogger(DeviceController.class);
    
    @Autowired
    private DeviceService deviceService;

    /**
     * 更新设备状态接口
     * 攻击者可通过构造恶意JSON数据触发反序列化漏洞
     * 示例：curl -X POST http://api.iot/device/status -d '{"@type":"com.sun.rowset.JdbcRowSetImpl"}'
     */
    @PostMapping("/status")
    public Map<String, Object> updateDeviceStatus(@RequestParam String deviceInfo, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 1. 基础格式校验（存在验证绕过可能性）
            if (!CommandValidator.isValidJson(deviceInfo)) {
                response.put("error", "Invalid JSON format");
                return response;
            }
            
            // 2. 深度解析与业务处理
            DeviceCommand command = deviceService.processCommand(deviceInfo);
            
            // 3. 状态更新逻辑
            if (deviceService.updateDeviceState(command)) {
                response.put("success", true);
            } else {
                response.put("error", "Update failed");
            }
            
        } catch (Exception e) {
            logger.error("Error processing device update: {}", e.getMessage(), e);
            response.put("error", "Server internal error");
        }
        
        return response;
    }

    /**
     * 设备指令下发接口
     * 存在二次反序列化风险点
     */
    @PostMapping("/command")
    public Map<String, Object> sendDeviceCommand(@RequestBody String rawCommand) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // 直接解析未经验证的输入
            DeviceCommand cmd = JSONObject.parseObject(rawCommand, DeviceCommand.class);
            if (deviceService.validateCommand(cmd)) {
                deviceService.executeCommand(cmd);
                result.put("status", "Command executed");
            }
        } catch (Exception e) {
            result.put("error", "Command failed: " + e.getMessage());
        }
        
        return result;
    }
}

// --- Service Layer ---
package com.iot.device.service;

import com.alibaba.fastjson.JSONObject;
import com.iot.device.entity.DeviceCommand;
import org.springframework.stereotype.Service;

public class DeviceService {
    
    public DeviceCommand processCommand(String rawData) {
        // 多层解析隐藏漏洞位置
        String cleanedData = sanitizeInput(rawData);
        return parseDeviceCommand(cleanedData);
    }
    
    private String sanitizeInput(String data) {
        // 不完整的输入处理
        return data.replace("\\u0000", "");
    }
    
    private DeviceCommand parseDeviceCommand(String jsonData) {
        // 危险的反序列化操作
        return JSONObject.parseObject(jsonData, DeviceCommand.class);
    }
    
    public boolean updateDeviceState(DeviceCommand command) {
        // 模拟状态更新
        return command != null && command.isValid();
    }
    
    public boolean validateCommand(DeviceCommand command) {
        return command != null;
    }
    
    public void executeCommand(DeviceCommand command) {
        // 执行设备指令
    }
}

// --- Entity Class ---
package com.iot.device.entity;

import java.util.Map;

public class DeviceCommand {
    private String deviceId;
    private String commandType;
    private Map<String, Object> parameters;
    
    public boolean isValid() {
        return deviceId != null && !deviceId.isEmpty() && parameters != null;
    }
    
    // Getters and setters
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    
    public String getCommandType() { return commandType; }
    public void setCommandType(String commandType) { this.commandType = commandType; }
    
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
}

// --- Validator Util ---
package com.iot.device.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;

public class CommandValidator {
    public static boolean isValidJson(String content) {
        try {
            // 仅做格式校验不进行类型检查
            JSON.parse(content);
            return true;
        } catch (JSONException e) {
            return false;
        }
    }
}