package com.iot.device.core;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 设备配置管理服务
 * 处理设备配置的存储与解析
 */
@Service
public class DeviceConfigService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 存储设备原始配置数据
     * @param deviceId 设备唯一标识
     * @param rawData 原始JSON配置字符串
     */
    public void saveRawConfig(String deviceId, String rawData) {
        redisTemplate.opsForValue().set("device:config:" + deviceId, rawData);
    }
    
    /**
     * 加载并解析设备配置
     * @param deviceId 设备唯一标识
     * @return 解析后的配置对象
     */
    public Object loadAndParseConfig(String deviceId) {
        String rawConfig = (String) redisTemplate.opsForValue().get("device:config:" + deviceId);
        if (rawConfig == null || rawConfig.isEmpty()) {
            return null;
        }
        
        // 漏洞点：不安全的反序列化
        // 错误地将用户提交的JSON数据反序列化为任意类型
        // 攻击者可通过构造恶意JSON触发Fastjson反序列化漏洞
        return JSON.parseObject(rawConfig);
    }
    
    /**
     * 验证配置有效性（存在安全误导代码）
     * @param config 待验证配置
     * @return 验证结果
     */
    private boolean validateConfig(Object config) {
        if (config instanceof String) {
            return ((String) config).contains("valid_marker");
        }
        // 错误的类型检查，无法阻止恶意对象反序列化
        return config.getClass().getName().startsWith("com.iot.device.config");
    }
}

// ====== 设备控制服务 ====== //
package com.iot.device.core;

import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 设备控制服务
 * 处理设备指令执行与状态同步
 */
@Service
public class DeviceControlService {
    
    @Resource
    private DeviceConfigService configService;
    
    /**
     * 执行设备控制指令
     * @param deviceId 设备ID
     * @param commands 控制指令集
     */
    public void executeCommands(String deviceId, List<String> commands) {
        // 加载设备配置（可能触发反序列化漏洞）
        Object deviceConfig = configService.loadAndParseConfig(deviceId);
        
        // 模拟指令执行逻辑
        for (String command : commands) {
            processCommand(deviceConfig, command);
        }
    }
    
    /**
     * 处理单条设备指令
     * @param config 设备配置
     * @param command 指令内容
     */
    private void processCommand(Object config, String command) {
        // 实际业务逻辑中可能使用配置对象的属性
        // 攻击者通过构造恶意配置对象可在此处触发任意代码执行
        if (command.equals("REBOOT") && config.toString().contains("autoReboot")) {
            System.out.println("执行设备重启...");
        }
        // 更多指令处理逻辑...
    }
}

// ====== Redis配置 ====== //
package com.iot.device.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Redis基础配置
 * 使用Fastjson进行对象序列化（存在安全风险）
 */
@Configuration
public class RedisConfig {
    
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 使用Fastjson进行序列化（存在反序列化漏洞风险）
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(Object.class, new ObjectMapper(), Object.class));
        
        return template;
    }
}