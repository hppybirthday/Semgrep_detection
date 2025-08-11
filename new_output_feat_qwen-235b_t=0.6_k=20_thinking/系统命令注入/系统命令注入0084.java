package com.smartiot.controller;

import com.smartiot.service.DeviceService;
import com.smartiot.util.CommandExecutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/device")
public class DeviceControlController {
    @Autowired
    private DeviceService deviceService;

    /**
     * IoT设备数据采集接口
     * 示例请求: /device/collect?deviceId=SENSOR-01;rm -rf /
     */
    @GetMapping("/collect")
    public String collectData(@RequestParam String deviceId) {
        try {
            // 1. 验证设备ID格式
            if (!isValidDeviceId(deviceId)) {
                return "Invalid device ID format";
            }
            
            // 2. 获取采集命令（隐藏的漏洞点）
            String command = deviceService.getCollectionCommand(deviceId);
            
            // 3. 执行系统命令（实际执行点）
            return CommandExecutor.execute(command);
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * 设备状态检查接口（存在误导性安全检查）
     */
    @GetMapping("/status")
    public String checkStatus(HttpServletRequest request) {
        String device = request.getParameter("device");
        
        // 表面的安全检查（可被绕过）
        if (device != null && device.contains("..") || device.contains("/")) {
            return "Invalid device path";
        }
        
        // 调用存在漏洞的命令执行
        return CommandExecutor.execute("/opt/iot/bin/check_status " + device);
    }

    /**
     * 验证设备ID格式（存在正则表达式漏洞）
     * 误认为可以阻止命令注入
     */
    private boolean isValidDeviceId(String id) {
        // 仅允许字母数字和短横线（看似安全但存在绕过可能）
        return Pattern.matches("^[a-zA-Z0-9\\-]+$", id);
    }
}

// --- Service Layer ---
package com.smartiot.service;

import org.springframework.stereotype.Service;

@Service
public class DeviceService {
    /**
     * 获取设备数据采集命令（存在逻辑混淆）
     * 实际拼接用户输入到命令中
     */
    public String getCollectionCommand(String deviceId) {
        // 复杂的业务逻辑掩盖漏洞
        String baseCommand = prepareBaseCommand();
        String params = buildParameters(deviceId);
        
        // 关键漏洞点：未正确处理用户输入
        return baseCommand + " " + params;
    }

    private String prepareBaseCommand() {
        // 从配置文件读取基础命令（假设可信）
        return "/opt/iot/bin/data_collector";
    }

    private String buildParameters(String deviceId) {
        // 参数构建过程（隐藏的命令注入点）
        return "--device=" + deviceId + " --format=json";
    }
}

// --- Util Class ---
package com.smartiot.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    /**
     * 执行系统命令（真实执行点）
     */
    public static String execute(String command) throws IOException {
        try {
            // 使用Runtime.exec直接执行命令（危险模式）
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
        } catch (IOException e) {
            throw new IOException("Command execution failed: " + e.getMessage());
        }
    }
}