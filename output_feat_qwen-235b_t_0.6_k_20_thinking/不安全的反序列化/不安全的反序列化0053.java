package com.example.demo;

import com.alibaba.fastjson.JSON;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class VulnerableController {
    @PostMapping("/update")
    public ResponseEntity<String> updateConfig(@RequestParam String configData) {
        try {
            // 不安全的反序列化操作
            ConfigMap configMap = JsonUtils.jsonToObject(configData, ConfigMap.class);
            return ResponseEntity.ok("Config updated: " + configMap.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing config");
        }
    }
}

class JsonUtils {
    // 使用FastJSON进行反序列化且未配置安全限制
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        return (T) JSON.parseObject(json, clazz);
    }
}

class ConfigMap {
    private Map<String, Object> settings = new HashMap<>();

    public Map<String, Object> getSettings() {
        return settings;
    }

    public void setSettings(Map<String, Object> settings) {
        this.settings = settings;
    }

    @Override
    public String toString() {
        return "ConfigMap{" + "settings=" + settings + \'}\';
    }
}