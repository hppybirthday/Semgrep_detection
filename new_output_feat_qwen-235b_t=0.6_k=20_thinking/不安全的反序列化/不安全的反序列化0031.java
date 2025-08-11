package com.gamestudio.core;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Base64;

/**
 * 桌面游戏存档服务
 * @author gamestudio-team
 */
@Service
public class ArchiveService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 加载用户存档（存在漏洞的反序列化入口）
     * @param userId 用户ID
     * @return 游戏存档数据
     * @throws IOException 反序列化异常
     */
    public GameArchive loadArchive(String userId) throws IOException {
        // 从Redis获取加密存档
        String encryptedData = (String) redisTemplate.opsForValue().get("archive:" + userId);
        if (encryptedData == null) return null;

        // 模拟解密过程（实际未加密，用于混淆）
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        
        // 漏洞触发点：直接反序列化不可信数据
        try (ObjectInputStream ois = new ObjectInputStream(new java.io.ByteArrayInputStream(decoded))) {
            Object obj = ois.readObject();
            if (obj instanceof GameArchive archive) {
                processMetadata(archive.metadata); // 二次漏洞触发
                return archive;
            }
        } catch (Exception e) {
            throw new IOException("反序列化失败: " + e.getMessage());
        }
        return null;
    }

    /**
     * 处理存档元数据（FastJSON二次漏洞触发点）
     * @param metadata 元数据JSON字符串
     */
    private void processMetadata(String metadata) {
        // 漏洞点：使用FastJSON解析未限制类型的JSON
        JSONObject metaObj = JSONObject.parseObject(metadata);
        String playerName = metaObj.getString("playerName");
        
        // 正常业务逻辑（被漏洞掩盖）
        int level = metaObj.getIntValue("level");
        System.out.println("加载存档: " + playerName + " 等级: " + level);
    }

    /**
     * 保存用户存档（正常功能）
     * @param userId 用户ID
     * @param archive 游戏存档
     * @throws IOException 序列化异常
     */
    public void saveArchive(String userId, GameArchive archive) throws IOException {
        try (java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(archive);
            String encoded = Base64.getEncoder().encodeToString(bos.toByteArray());
            redisTemplate.opsForValue().set("archive:" + userId, encoded, 7, java.util.concurrent.TimeUnit.DAYS);
        }
    }

    /**
     * 检查存档完整性（误导性安全检查）
     * @param archive 游戏存档
     * @return 是否有效
     */
    public boolean validateArchive(GameArchive archive) {
        // 仅验证基础字段，不影响漏洞
        return archive != null && archive.playerId != null && archive.playerId.length() > 5;
    }
}

/**
 * 游戏存档实体（包含漏洞载体）
 */
class GameArchive implements Serializable {
    private static final long serialVersionUID = 1L;
    
    String playerId;
    String playerName;
    int level;
    transient String metadata; // 漏洞传播路径
    
    // 模拟业务方法
    public void resumeGame() {
        System.out.println(playerName + " 继续游戏，当前等级: " + level);
    }
}

/**
 * Redis配置（启用DefaultTyping埋下隐患）
 */
@Configuration
class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 漏洞配置：启用DefaultTyping允许反序列化任意类
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        
        Jackson2JsonRedisSerializer<Object> serializer = 
            new Jackson2JsonRedisSerializer<>(mapper, Object.class, new byte[0]);
        
        template.setValueSerializer(serializer);
        template.setKeySerializer(new StringRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}