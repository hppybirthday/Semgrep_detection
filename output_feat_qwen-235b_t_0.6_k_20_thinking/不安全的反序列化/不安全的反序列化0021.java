package com.example.vulnerableapp;

import com.alibaba.fastjson.JSON;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/admin/config")
public class VulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }

    @PostMapping("/mall")
    public ResponseEntity<String> updateMallConfig(@RequestBody String body) {
        MallConfig config = JSON.parseObject(body, MallConfig.class);
        return ResponseEntity.ok("Mall config updated: " + config.toString());
    }

    @PostMapping("/express")
    public ResponseEntity<String> updateExpressConfig(@RequestBody String body) {
        ExpressConfig config = JSON.parseObject(body, ExpressConfig.class);
        return ResponseEntity.ok("Express config updated: " + config.toString());
    }

    @PostMapping("/wx")
    public ResponseEntity<String> updateWxConfig(@RequestBody String body) {
        WxConfig config = JSON.parseObject(body, WxConfig.class);
        return ResponseEntity.ok("Wx config updated: " + config.toString());
    }
}

class MallConfig {
    private String name;
    private int timeout;
    // getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
    public String toString() { return "MallConfig{name='" + name + "', timeout=" + timeout + "}"; }
}

class ExpressConfig {
    private String provider;
    private boolean enabled;
    // getters and setters
    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String toString() { return "ExpressConfig{provider='" + provider + "', enabled=" + enabled + "}"; }
}

class WxConfig {
    private String appId;
    private String secret;
    // getters and setters
    public String getAppId() { return appId; }
    public void setAppId(String appId) { this.appId = appId; }
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
    public String toString() { return "WxConfig{appId='" + appId + "', secret='" + secret + "'}"; }
}