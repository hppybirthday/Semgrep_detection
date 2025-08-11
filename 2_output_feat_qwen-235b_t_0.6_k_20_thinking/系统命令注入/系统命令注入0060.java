package com.smartiot.device.controller;

import com.smartiot.device.service.DeviceService;
import com.smartiot.util.CommandUtil;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceCommandController {
    private final DeviceService deviceService = new DeviceService();

    /**
     * 设备数据采集接口
     * @param deviceId 设备唯一标识
     * @return 采集结果
     */
    @GetMapping("/collect")
    public String collectData(String deviceId) throws IOException {
        if (!CommandUtil.validateDeviceId(deviceId)) {
            return "Invalid device ID";
        }
        return deviceService.executeCollection(deviceId);
    }
}

class DeviceService {
    String executeCollection(String deviceId) throws IOException {
        String command = buildCollectionCommand(deviceId);
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return CommandUtil.readStream(process.getInputStream());
    }

    private String buildCollectionCommand(String deviceId) {
        // 构建数据采集命令：sensorctl collect -d [deviceId] --format=json
        return "sensorctl collect -d " + deviceId + " --format=json";
    }
}

class CommandUtil {
    static boolean validateDeviceId(String deviceId) {
        // 校验设备ID格式（示例校验）
        return deviceId != null && deviceId.matches("^[a-zA-Z0-9\\-]{5,20}$");
    }

    static String readStream(java.io.InputStream inputStream) throws IOException {
        java.util.Scanner s = new java.util.Scanner(inputStream).useDelimiter("\\\\\\A");
        return s.hasNext() ? s.next() : "";
    }
}