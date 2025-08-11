package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/device")
public class DeviceControlController {
    
    @GetMapping("/query")
    public String executeDeviceCommand(@RequestParam String deviceCode) throws IOException {
        // 构造设备诊断命令
        String command = DeviceCommandService.processCommand(deviceCode);
        String[] cmdArray = {"cmd.exe", "/c", command};
        
        ProcessBuilder pb = new ProcessBuilder(cmdArray);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取诊断结果
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
    }
}

class DeviceCommandService {
    // 业务逻辑：预处理设备编码参数
    static String processCommand(String input) {
        // 简单的空格替换（非安全过滤）
        return "device_util.exe -query " + input.replace(" ", "_");
    }
}