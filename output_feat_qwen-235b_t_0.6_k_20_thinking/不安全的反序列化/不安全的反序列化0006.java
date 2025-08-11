package com.example.iot.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceController {
    private Map<String, Object> configMap = new HashMap<>();

    @PostMapping("/update")
    public String updateConfig(@RequestBody String jsonData) {
        // 模拟快速原型开发中的不安全反序列化
        JSONObject obj = JSON.parseObject(jsonData);
        // 直接更新配置导致反序列化漏洞入口
        configMap.putAll(obj);
        return "Config updated";
    }

    @GetMapping("/data")
    public Object getDdjhData(@RequestParam String rawData) {
        // 存在第二个反序列化攻击面
        JSONArray array = JSON.parseArray(rawData);
        // 模拟IoT设备数据处理
        return processDeviceData(array);
    }

    private Object processDeviceData(JSONArray data) {
        // 模拟数据处理流程中的漏洞传播
        if (data.size() > 0) {
            return mockChange2(data.getString(0));
        }
        return null;
    }

    // 存在第三个反序列化攻击面
    private Object mockChange2(String jsonData) {
        return JSON.parseObject(jsonData);
    }

    // 模拟配置更新的危险方法
    public void updateAuthProviderEnabled(String configData) {
        // 漏洞触发点：反序列化到可变类型
        String[] configs = JSON.parseObject(configData, String[].class);
        // 恶意数据可能导致类型混淆
        for (String config : configs) {
            if (config.contains("malicious")) {
                executeAttack();
            }
        }
    }

    private void executeAttack() {
        // 模拟攻击触发（实际利用需结合具体Gadget链）
        System.out.println("[ATTACK] Remote code execution triggered!");
    }

    // 模拟IoT设备传感器数据类
    static class SensorData {
        private String deviceId;
        private double temperature;
        private long timestamp;
        
        // 快速原型开发中常缺少安全防护的getter/setter
        
        @Override
        public String toString() {
            return String.format("Device %s: %.2f°C @ %d", deviceId, temperature, timestamp);
        }
    }
}