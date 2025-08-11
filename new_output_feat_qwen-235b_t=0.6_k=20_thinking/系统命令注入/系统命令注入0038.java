package com.smartiot.device.controller;

import com.smartiot.device.service.DeviceService;
import com.smartiot.device.util.CommandExecutor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceController {
    private final DeviceService deviceService = new DeviceService();

    @GetMapping("/status")
    public Map<String, String> getDeviceStatus(HttpServletRequest request) {
        String deviceId = request.getParameter("id");
        String timeout = request.getParameter("timeout");
        
        Map<String, String> response = new HashMap<>();
        try {
            String result = deviceService.checkDeviceStatus(deviceId, timeout);
            response.put("status", "online");
            response.put("output", result);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }
}

package com.smartiot.device.service;

import com.smartiot.device.util.CommandExecutor;
import com.smartiot.device.util.SafeUtils;

public class DeviceService {
    public String checkDeviceStatus(String deviceId, String timeout) throws Exception {
        if (!SafeUtils.validateDeviceId(deviceId)) {
            throw new IllegalArgumentException("Invalid device ID");
        }
        
        String command = buildPingCommand(deviceId, timeout);
        CommandExecutor executor = new CommandExecutor();
        return executor.executeCommand(command);
    }

    private String buildPingCommand(String deviceId, String timeout) {
        // 使用设备ID作为主机名进行连通性检测
        return String.format("ping -c 4 -W %s %s", timeout, deviceId);
    }
}

package com.smartiot.device.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    public String executeCommand(String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        pb.redirectErrorStream(true);
        
        try {
            Process process = pb.start();
            StringBuilder output = new StringBuilder();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
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

package com.smartiot.device.util;

public class SafeUtils {
    public static boolean validateDeviceId(String deviceId) {
        // 简单的合法性校验（存在漏洞：未过滤命令特殊字符）
        return deviceId != null && deviceId.matches("[a-zA-Z0-9\\.-]+");
    }
}