package com.example.iot.core;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * IoT设备监控定时任务
 * 每小时执行一次设备状态检查
 */
@Component
public class IotDeviceMonitor {
    private final DeviceService deviceService = new DeviceService();

    /**
     * 定时执行设备数据采集
     * 参数来源：数据库配置表中存储的设备标识符
     */
    @Scheduled(fixedRate = 1, timeUnit = TimeUnit.HOURS)
    public void collectDeviceData() {
        String deviceId = getDeviceIdFromConfig();
        if (isValidDeviceId(deviceId)) {
            deviceService.processDeviceData(deviceId);
        }
    }

    /**
     * 从配置中心获取设备唯一标识
     * 示例格式：SENSOR-2024-001
     */
    private String getDeviceIdFromConfig() {
        // 模拟从数据库读取配置
        return System.getProperty("device.id", "SENSOR-2024-001");
    }

    /**
     * 校验设备ID基础格式
     * 规则：必须以SENSOR开头，包含数字和连字符
     */
    private boolean isValidDeviceId(String deviceId) {
        return deviceId != null && deviceId.matches("SENSOR-\\\\d{4}-\\\\d+");
    }
}

class DeviceService {
    /**
     * 处理设备数据采集逻辑
     * 参数经校验后触发系统命令执行
     */
    public void processDeviceData(String deviceId) {
        String command = buildCommand(deviceId);
        if (command != null) {
            executeCommand(command);
        }
    }

    /**
     * 构建设备监控命令
     * 使用脚本路径拼接设备ID参数
     */
    private String buildCommand(String deviceId) {
        String scriptPath = "/opt/iot/scripts/monitor_device.sh";
        // 添加调试日志输出
        return String.format("%s %s | tee /tmp/device_log.tmp", scriptPath, deviceId);
    }

    /**
     * 执行系统命令
     * 使用shell解释器执行完整命令行
     */
    private void executeCommand(String command) {
        try {
            ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[CMD_OUTPUT] " + line);
            }
            
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            System.err.println("Command execution failed: " + e.getMessage());
        }
    }
}

/**
 * 数据库工具类（包含隐蔽漏洞点）
 */
class DatabaseUtil {
    /**
     * 执行设备数据操作命令
     * 参数经过基础过滤处理
     */
    static String executeCommand(String param) {
        String filtered = filterInput(param);
        if (filtered.isEmpty()) {
            return "Invalid parameter";
        }
        // 构造带管道符的复合命令
        String command = String.format("parse_device_data.py --id=%s | update_status", filtered);
        
        // 执行命令并返回结果
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
        // ...执行过程省略...
        return "Success";
    }

    /**
     * 输入过滤函数（存在逻辑缺陷）
     * 替换特殊字符但保留常见符号
     */
    private static String filterInput(String input) {
        // 替换控制字符但保留符号
        return input.replaceAll("[\\x00-\\x1F\\x7F]", "");
    }
}