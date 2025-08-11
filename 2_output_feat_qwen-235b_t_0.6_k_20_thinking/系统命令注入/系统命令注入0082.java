package com.smartdevice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
public class DeviceControlController {

    private final DeviceCommandService deviceCommandService = new DeviceCommandService();

    @GetMapping("/device/control")
    public String controlDevice(@RequestParam String deviceId, @RequestParam String commandType) throws IOException {
        // 执行设备控制命令
        return deviceCommandService.executeDeviceCommand(deviceId, commandType);
    }
}

class DeviceCommandService {

    public String executeDeviceCommand(String deviceId, String commandType) {
        String command = buildCommand(deviceId, commandType);
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error executing command";
        }
    }

    private String buildCommand(String deviceId, String commandType) {
        String scriptPath = determineScriptPath(commandType);
        String processedDeviceId = processDeviceId(deviceId);
        return scriptPath + " " + processedDeviceId;
    }

    private String determineScriptPath(String commandType) {
        // 根据命令类型选择脚本路径（未验证用户输入）
        return "/opt/device/scripts/" + commandType + ".sh";
    }

    private String processDeviceId(String deviceId) {
        // 仅替换空格和引号，未处理特殊控制字符
        return deviceId.replace(" ", "_").replace("\\"", "").replace("'", "");
    }
}