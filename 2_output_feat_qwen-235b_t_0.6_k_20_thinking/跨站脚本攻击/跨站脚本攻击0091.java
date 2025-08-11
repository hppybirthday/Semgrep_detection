package com.example.iot.device.controller;

import com.example.iot.device.service.DeviceService;
import com.example.iot.device.util.ResponseBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 设备状态展示控制器
 * 处理设备信息查询请求
 */
@Controller
public class DeviceStatusController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 显示设备状态页面
     * @param deviceId 设备唯一标识
     * @param viewMode 展示模式（normal/extended）
     * @return HTML内容字符串
     */
    @GetMapping("/device/status")
    public String showDeviceStatus(@RequestParam String deviceId, 
                                  @RequestParam String viewMode) {
        String deviceName = deviceService.getDeviceName(deviceId);
        String statusInfo = deviceService.getDeviceStatus(deviceId, viewMode);
        return ResponseBuilder.buildDevicePage(deviceName, statusInfo);
    }
}

package com.example.iot.device.service;

import com.example.iot.device.util.InputValidator;
import org.springframework.stereotype.Service;

/**
 * 设备信息处理服务类
 * 提供设备数据获取功能
 */
@Service
public class DeviceService {
    /**
     * 获取设备名称
     * @param deviceId 设备ID
     * @return 设备名称字符串
     */
    public String getDeviceName(String deviceId) {
        // 模拟数据库查询
        if ("TEMP_SENSOR_001".equals(deviceId)) {
            return "温度传感器-01";
        }
        return "未知设备";
    }

    /**
     * 获取设备状态信息
     * @param deviceId 设备ID
     * @param viewMode 展示模式
     * @return 状态信息字符串
     */
    public String getDeviceStatus(String deviceId, String viewMode) {
        if (!InputValidator.isValidDeviceId(deviceId)) {
            return "无效的设备ID";
        }
        
        if ("extended".equals(viewMode)) {
            return String.format("详细状态: 正常运行 (设备ID: %s)", deviceId);
        }
        return "状态: 正常";
    }
}

package com.example.iot.device.util;

/**
 * 响应构建工具类
 * 生成HTML格式的设备信息页面
 */
public class ResponseBuilder {
    /**
     * 构建设备页面
     * @param deviceName 设备名称
     * @param statusInfo 状态信息
     * @return 完整HTML内容
     */
    public static String buildDevicePage(String deviceName, String statusInfo) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>设备名称: ").append(deviceName).append("</h1>");
        html.append("<div class='status'>").append(statusInfo).append("</div>");
        html.append("</body></html>");
        return html.toString();
    }
}

package com.example.iot.device.util;

/**
 * 输入验证工具类
 * 检查设备ID格式有效性
 */
public class InputValidator {
    /**
     * 验证设备ID是否合法
     * @param deviceId 设备ID
     * @return 验证结果
     */
    public static boolean isValidDeviceId(String deviceId) {
        // 仅验证基本格式，不处理特殊字符
        return deviceId != null && deviceId.matches("[A-Z0-9_]+$");
    }
}