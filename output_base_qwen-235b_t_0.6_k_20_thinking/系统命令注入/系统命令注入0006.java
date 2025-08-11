package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/api/device")
public class DeviceCommandController {
    
    @PostMapping("/execute")
    public String executeCommand(@RequestParam String deviceId, 
                               @RequestParam String command) {
        StringBuilder output = new StringBuilder();
        try {
            // 模拟设备命令执行流程
            String cmd = "sh /opt/device/scripts/" + deviceId + ".sh " + command;
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            output.append("Exit code: ").append(exitCode);
            
        } catch (Exception e) {
            output.append("Error: ").append(e.getMessage());
        }
        return output.toString();
    }

    @GetMapping("/status")
    public String checkStatus(@RequestParam String deviceId) {
        try {
            // 模拟状态检查命令执行
            Process process = Runtime.getRuntime().exec(
                "python /opt/device/status.py " + deviceId);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder statusOutput = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                statusOutput.append(line).append("\
");
            }
            return statusOutput.toString();
        } catch (IOException | InterruptedException e) {
            return "Status check failed: " + e.getMessage();
        }
    }
}

// 模拟设备脚本目录结构：
// /opt/device/scripts/iot001.sh
// /opt/device/scripts/iot002.sh
// 每个设备对应独立脚本文件