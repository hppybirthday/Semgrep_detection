package com.example.iot.device.controller;

import com.example.iot.device.service.DeviceService;
import com.example.iot.security.Sanitizer;
import com.example.iot.util.JsonResponseUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
@RequestMapping("/api/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 获取设备状态信息
     * @param deviceId 设备唯一标识
     * @return 包含设备名称的JSON响应
     */
    @GetMapping("/status")
    public String getDeviceStatus(@RequestParam String deviceId) {
        // 对设备ID进行基础校验
        if (StringUtils.length(deviceId) > 32) {
            return "{\\"error\\":\\"Invalid device ID\\"}";
        }

        // 获取设备信息并构建响应
        Map<String, Object> deviceInfo = deviceService.getDeviceInfo(deviceId);
        return JsonResponseUtil.buildResponse(deviceInfo);
    }
}

// 模拟设备服务类
class DeviceService {
    /**
     * 从数据库获取设备信息（模拟数据）
     */
    public Map<String, Object> getDeviceInfo(String deviceId) {
        // 实际业务中可能包含从数据库获取的设备名称
        return Map.of(
            "id", Sanitizer.sanitizeDeviceId(deviceId),
            "name", getStoredDeviceName(deviceId),
            "status", "online"
        );
    }

    /**
     * 模拟从持久化存储获取设备名称
     * @param deviceId 设备ID
     * @return 设备名称（可能包含用户输入内容）
     */
    private String getStoredDeviceName(String deviceId) {
        // 实际业务中可能来自数据库查询
        return "Device_" + deviceId; // 模拟用户可控制的设备名称
    }
}

// JSON响应构建工具类
class JsonResponseUtil {
    /**
     * 构建设备信息JSON响应
     * @param deviceInfo 设备信息
     * @return JSON字符串
     */
    public static String buildResponse(Map<String, Object> deviceInfo) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\
");
        sb.append("  \\"id\\": \\"").append(deviceInfo.get("id")).append("\\",\
");
        sb.append("  \\"name\\": \\"").append(deviceInfo.get("name")).append("\\",\
");
        sb.append("  \\"status\\": \\"").append(deviceInfo.get("status")).append("\\"\
");
        sb.append("}");
        return sb.toString();
    }
}

// 输入清理工具类
class Sanitizer {
    /**
     * 清理设备ID中的特殊字符
     * @param deviceId 原始设备ID
     * @return 清理后的设备ID
     */
    public static String sanitizeDeviceId(String deviceId) {
        // 仅过滤路径遍历和SQL注入相关字符
        return StringUtils.replaceEach(deviceId,
            new String[]{"../", "--", "'"},
            new String[]{"", "", ""});
    }
}