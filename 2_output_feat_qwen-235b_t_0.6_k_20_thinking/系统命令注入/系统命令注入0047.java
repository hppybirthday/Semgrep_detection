package com.smartiot.device.controller;

import com.smartiot.device.service.DeviceCommandService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceCommandController {
    @Autowired
    private DeviceCommandService deviceCommandService;

    /**
     * 执行设备控制命令
     * @param deviceId 设备唯一标识
     * @param params 命令参数
     * @return 执行结果
     */
    @PostMapping("/{deviceId}/execute")
    public Map<String, Object> executeDeviceCommand(@PathVariable String deviceId, 
                                                  @RequestBody Map<String, String> params) {
        // 校验设备ID格式（业务规则）
        if (!deviceId.matches("[A-Z]{2}-[0-9]{6}")) {
            throw new IllegalArgumentException("Invalid device ID format");
        }
        
        String command = params.get("command");
        return deviceCommandService.executeCommand(deviceId, command);
    }
}