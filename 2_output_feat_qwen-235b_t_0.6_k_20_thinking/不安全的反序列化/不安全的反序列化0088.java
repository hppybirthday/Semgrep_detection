package com.example.iot.device;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import com.alibaba.fastjson.support.spring.GenericFastJsonRedisSerializer;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.io.Serializable;
import java.util.Map;

@RestController
@RequestMapping("/device")
class DeviceController {
    @Resource
    DeviceService deviceService;

    @PostMapping("/addConfig")
    ResponseEntity<Void> addDeviceConfig(@RequestParam String dbKey, @RequestBody DeviceConfig config) {
        deviceService.addDeviceConfig(dbKey, config);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/batchSetStatus")
    ResponseEntity<Void> batchSetStatus(@RequestParam String dbKey, @RequestParam String status) {
        deviceService.batchSetStatus(dbKey, status);
        return ResponseEntity.ok().build();
    }
}

@Service
class DeviceService {
    @Resource
    RedisTemplate<String, Object> redisTemplate;

    void addDeviceConfig(String dbKey, DeviceConfig config) {
        redisTemplate.opsForValue().set(dbKey, config, 5, java.util.concurrent.TimeUnit.MINUTES);
    }

    void batchSetStatus(String dbKey, String status) {
        DeviceConfig config = (DeviceConfig) redisTemplate.opsForValue().get(dbKey);
        if (config != null) {
            config.setCurrentStatus(status);
            redisTemplate.opsForValue().set("status:" + dbKey, config, 5, java.util.concurrent.TimeUnit.MINUTES);
        }
    }
}

@Configuration
class RedisConfig {
    @Bean
    @ConditionalOnMissingBean
    RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericFastJsonRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new GenericFastJsonRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}

class DeviceConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    private String deviceId;
    private String currentStatus;
    private Map<String, String> metadata;

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public String getCurrentStatus() { return currentStatus; }
    public void setCurrentStatus(String currentStatus) { this.currentStatus = currentStatus; }

    public Map<String, String> getMetadata() { return metadata; }
    public void setMetadata(Map<String, String> metadata) { this.metadata = metadata; }
}