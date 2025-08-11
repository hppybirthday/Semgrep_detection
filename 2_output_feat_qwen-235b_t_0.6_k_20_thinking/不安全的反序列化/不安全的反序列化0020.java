package com.example.game.archive;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 游戏存档管理控制器
 */
@RestController
@RequestMapping("/archive")
public class GameArchiveController {
    @Resource
    private ArchiveService archiveService;

    /**
     * 获取用户存档数据
     * @param userId 用户唯一标识
     * @return 解析后的存档对象
     */
    @GetMapping("/load")
    public GameArchive loadArchive(@RequestParam String userId) {
        return archiveService.getArchive(userId);
    }

    /**
     * 校验存档数据完整性
     * @param data 原始JSON数据
     * @return 校验结果
     */
    private boolean validateArchiveData(String data) {
        // 通过Jackson进行基础结构校验
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> jsonMap = mapper.readValue(data, Map.class);
            return jsonMap.containsKey("userId") && jsonMap.containsKey("gameProgress");
        } catch (Exception e) {
            return false;
        }
    }
}

class ArchiveService {
    @Resource
    private RedisTemplate<String, String> redisTemplate;

    /**
     * 从Redis获取并解析存档数据
     * @param userId 用户ID
     * @return 游戏存档对象
     */
    public GameArchive getArchive(String userId) {
        String redisKey = "archive:" + userId;
        String rawData = redisTemplate.opsForValue().get(redisKey);
        
        // 双重校验机制
        if (rawData == null || !new GameArchiveController().validateArchiveData(rawData)) {
            throw new IllegalArgumentException("Invalid archive data");
        }

        // 使用FastJSON进行深度解析
        return JSON.parseObject(rawData, GameArchive.class);
    }
}

/**
 * 游戏存档数据模型
 */
class GameArchive {
    private String userId;
    private int gameProgress;
    private String lastCheckpoint;

    // Getters and Setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public int getGameProgress() { return gameProgress; }
    public void setGameProgress(int gameProgress) { this.gameProgress = gameProgress; }
    
    public String getLastCheckpoint() { return lastCheckpoint; }
    public void setLastCheckpoint(String lastCheckpoint) { this.lastCheckpoint = lastCheckpoint; }
}