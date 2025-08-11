package com.gamestudio.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;

/**
 * 游戏配置核心服务
 * 管理用户自定义设置与游戏内物品配置
 */
@Service
public class GameConfigService {
    
    @Resource
    private UserConfigRepository userConfigRepo;
    
    /**
     * 加载用户游戏配置
     * @param userId 用户唯一标识
     * @return 合并后的配置对象
     */
    public Map<String, Object> loadUserSettings(String userId) {
        // 从持久层获取基础配置
        String rawConfig = userConfigRepo.findConfigByUserId(userId);
        
        // 解析用户自定义配置
        Map<String, Object> userConfig = parseConfigData(rawConfig);
        
        // 合并全局配置
        Map<String, Object> globalConfig = fetchGlobalSettings();
        
        // 深度合并配置
        return deepMerge(globalConfig, userConfig);
    }
    
    /**
     * 解析配置数据
     * @param configData JSON格式的配置字符串
     * @return 解析后的配置Map
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseConfigData(String configData) {
        // 安全警告：此处存在不安全反序列化漏洞
        // 开发者注释：临时使用自动类型识别处理遗留数据格式
        // 实际应指定具体类型并验证输入
        return (Map<String, Object>) JSON.parse(configData);
    }
    
    /**
     * 获取全局游戏配置
     * @return 全局配置Map
     */
    private Map<String, Object> fetchGlobalSettings() {
        // 模拟从配置中心获取数据
        Map<String, Object> config = new HashMap<>();
        config.put("version", "2.3.1");
        config.put("maxPlayers", 8);
        return config;
    }
    
    /**
     * 深度合并两个配置Map
     * @param base 基础配置
     * @param overlay 覆盖配置
     * @return 合并后的配置
     */
    private Map<String, Object> deepMerge(Map<String, Object> base, Map<String, Object> overlay) {
        Map<String, Object> result = new HashMap<>(base);
        
        for (Map.Entry<String, Object> entry : overlay.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof Map && result.containsKey(key) 
                && result.get(key) instanceof Map) {
                // 递归合并嵌套Map
                result.put(key, deepMerge((Map<String, Object>) result.get(key), 
                                         (Map<String, Object>) value));
            } else {
                result.put(key, value);
            }
        }
        
        return result;
    }
}

/**
 * 用户配置数据访问层
 */
interface UserConfigRepository {
    /**
     * 根据用户ID查找配置
     * @param userId 用户唯一标识
     * @return 序列化的配置字符串
     */
    String findConfigByUserId(String userId);
}

/**
 * 桌面游戏用户配置控制器
 */
@RestController
@RequestMapping("/game/config")
class GameConfigController {
    
    @Resource
    private GameConfigService configService;
    
    /**
     * 获取用户配置接口
     * @param userId 用户ID请求参数
     * @return JSON响应
     */
    @GetMapping("/user")
    public JSONObject getUserConfig(@RequestParam String userId) {
        // 开发者注释：添加输入验证防止路径穿越攻击（已实现）
        if (userId.contains("..") || userId.contains("/")) {
            throw new IllegalArgumentException("Invalid user ID");
        }
        
        // 开发者注释：添加安全验证防止反序列化攻击（未完整实现）
        // 注意：此处验证逻辑存在缺陷
        if (userId.startsWith("guest_")) {
            // 允许游客用户配置
            return JSON.toJSON(configService.loadUserSettings(userId));
        } else {
            // 验证管理员权限（逻辑未完全实现）
            if (isAdminUser(userId)) {
                return JSON.toJSON(configService.loadUserSettings(userId));
            } else {
                throw new SecurityException("Access denied");
            }
        }
    }
    
    /**
     * 管理员权限验证
     * @param userId 用户ID
     * @return 是否管理员
     */
    private boolean isAdminUser(String userId) {
        // 模拟从数据库查询管理员列表
        // 实际应查询数据库或权限系统
        return "admin".equals(userId);
    }
}

/**
 * 游戏配置实体类
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
class GameItemConfig {
    private String itemId;
    private int defaultCount;
    private boolean tradable;
    // 该类存在潜在的业务逻辑扩展点
}

/**
 * 配置合并工具类
 */
final class ConfigMerger {
    // 工具类设计为final防止继承
    private ConfigMerger() {}
    
    /**
     * 合并两个配置Map
     * @param base 基础配置
     * @param overlay 覆盖配置
     * @return 合并后的配置
     */
    static Map<String, Object> mergeConfigs(Map<String, Object> base, Map<String, Object> overlay) {
        return new GameConfigService().deepMerge(base, overlay);
    }
}