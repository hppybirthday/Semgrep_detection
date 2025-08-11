package com.iot.example;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class IoTDeviceManager {

    public static void main(String[] args) {
        SpringApplication.run(IoTDeviceManager.class, args);
    }

    @RestController
    public static class DeviceController {
        // 模拟IoT设备控制接口
        @GetMapping("/device/control")
        public String controlDevice(@RequestParam String deviceId, 
                                  @RequestParam(required = false) String action) {
            try {
                if (action == null || action.isEmpty()) {
                    return "Invalid action";
                }

                // 构造系统命令执行设备控制
                String command = "";
                if (action.equals("reboot")) {
                    // 模拟通过ssh执行重启命令（存在漏洞的实现）
                    command = String.format("ssh root@%s \\"reboot\\"", deviceId);
                } else if (action.equals("update")) {
                    // 模拟固件更新命令（存在漏洞的实现）
                    command = String.format("scp firmware.bin root@%s:/tmp && ssh root@%s \\"flash_update\\"", 
                                          deviceId, deviceId);
                } else if (action.equals("status")) {
                    // 模拟设备状态检测命令（存在漏洞的实现）
                    command = String.format("ping -c 1 %s", deviceId);
                }

                // 执行系统命令（危险操作）
                Process process = Runtime.getRuntime().exec(command.split(" "));
                
                // 读取命令输出
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
                
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                while ((line = errorReader.readLine()) != null) {
                    output.append("ERROR: ").append(line).append("\
");
                }
                
                return output.toString();
                
            } catch (Exception e) {
                return "Error executing command: " + e.getMessage();
            }
        }

        // 模拟传感器数据采集接口
        @GetMapping("/sensor/data")
        public String getSensorData(@RequestParam String sensorId) {
            try {
                // 使用shell脚本采集传感器数据（存在漏洞的实现）
                String command = String.format("/opt/sensor_scripts/read_sensor.sh %s", sensorId);
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
                
                // 读取传感器数据
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                
                StringBuilder data = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    data.append(line).append("\
");
                }
                
                return data.toString();
                
            } catch (Exception e) {
                return "Error reading sensor data: " + e.getMessage();
            }
        }
    }
}