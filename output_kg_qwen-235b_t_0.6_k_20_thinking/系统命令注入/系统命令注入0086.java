package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/device")
public class IoTDeviceController {
    
    @GetMapping("/status")
    public String getDeviceStatus(@RequestParam String deviceId) {
        try {
            // 模拟执行设备状态查询命令
            String command = "python /opt/scripts/check_device.py --id " + deviceId;
            Process process = Runtime.getRuntime().exec(command);
            
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
            
            String errorLine;
            while ((errorLine = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(errorLine).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
    
    @PostMapping("/control")
    public String controlDevice(@RequestParam String action, 
                              @RequestParam String param) {
        try {
            // 模拟执行设备控制命令
            String command = "bash /opt/scripts/device_ctl.sh -a " + action + " -p " + param;
            Process process = Runtime.getRuntime().exec(command);
            
            // 等待命令执行完成
            process.waitFor();
            
            return "Command executed with exit code: " + process.exitValue();
            
        } catch (Exception e) {
            return "Error controlling device: " + e.getMessage();
        }
    }
    
    @GetMapping("/logs")
    public String getDeviceLogs(@RequestParam String days) {
        try {
            // 模拟获取设备日志
            ProcessBuilder builder = new ProcessBuilder(
                "sh", "-c", "cat /var/log/device_logs.txt | grep -A 5 \\"$(date -d '-" + days + " days' '+%Y-%m-%d')\\""");
            Process process = builder.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error reading logs: " + e.getMessage();
        }
    }
}