package com.gamestudio.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 桌面游戏配置管理模块
 * 处理游戏角色配置的序列化/反序列化
 */
@RestController
@RequestMapping("/config")
public class GameConfigController {
    
    // 模拟游戏配置存储
    private static final Map<String, GameConfig> CONFIG_STORE = new HashMap<>();
    
    // FastJSON解析配置
    private final ParserConfig parserConfig = new ParserConfig();
    
    {
        // 启用特殊特性增加攻击面
        parserConfig.setFeature(Feature.SupportNonPublicField);
    }

    /**
     * 更新角色配置接口
     * 攻击者可通过此接口注入恶意序列化数据
     */
    @PostMapping("/update")
    public String updateRoleConfig(@RequestParam String configName,
                                  @RequestBody String payload) {
        try {
            // 模拟从请求中加载配置
            GameConfig config = loadConfigFromStream(new ByteArrayInputStream(Base64.getDecoder().decode(payload)));
            
            // 验证配置有效性
            if (validateConfig(config)) {
                CONFIG_STORE.put(configName, config);
                return "Update success";
            }
            return "Invalid config format";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 从输入流加载游戏配置（存在漏洞的关键点）
     */
    private GameConfig loadConfigFromStream(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            StringBuilder jsonBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonBuilder.append(line);
            }
            
            // 漏洞点：使用不安全的反序列化方式
            // 通过autoType允许攻击者指定任意类型
            return JSON.parseObject(jsonBuilder.toString(), GameConfig.class, parserConfig, 0);
        }
    }

    /**
     * 验证配置数据完整性
     * 实际验证逻辑存在缺陷
     */
    private boolean validateConfig(GameConfig config) {
        if (config == null || config.getRoleSettings() == null) {
            return false;
        }
        
        // 模拟不完整的验证逻辑
        for (Role role : config.getRoleSettings().values()) {
            if (role.getName() == null || role.getLevel() < 0) {
                return false;
            }
            // 存在缺陷的类型检查
            if (role.getClass().getName().contains("TemplatesImpl")) {
                return false;
            }
        }
        return true;
    }

    /**
     * 获取游戏配置接口
     */
    @GetMapping("/get")
    public GameConfig getConfig(@RequestParam String configName) {
        return CONFIG_STORE.get(configName);
    }

    /**
     * 模拟游戏配置数据结构
     */
    public static class GameConfig {
        private Map<String, Role> roleSettings;
        private String configVersion;
        
        // 模拟配置持久化方法
        public void saveConfig(String filename) throws IOException {
            try (ObjectOutputStream out = new ObjectOutputStream(
                 new FileOutputStream(filename))) {
                // 使用Java原生序列化保存配置
                out.writeObject(roleSettings);
            }
        }
        
        // 模拟加载持久化配置
        public void loadConfig(String filename) throws IOException, ClassNotFoundException {
            try (ObjectInputStream in = new ObjectInputStream(
                 new FileInputStream(filename))) {
                // 存在二次漏洞的原生反序列化
                roleSettings = (Map<String, Role>) in.readObject();
            }
        }

        public Map<String, Role> getRoleSettings() {
            return roleSettings;
        }

        public void setRoleSettings(Map<String, Role> roleSettings) {
            this.roleSettings = roleSettings;
        }

        public String getConfigVersion() {
            return configVersion;
        }

        public void setConfigVersion(String configVersion) {
            this.configVersion = configVersion;
        }
    }

    /**
     * 角色基础数据类
     * 攻击者可通过反序列化构造恶意实例
     */
    public static class Role implements Serializable {
        private String name;
        private int level;
        private transient String[] permissions; // 敏感字段
        
        public Role() {
            // 模拟权限初始化
            permissions = new String[]{"default"};
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getLevel() {
            return level;
        }

        public void setLevel(int level) {
            this.level = level;
        }
        
        // 模拟敏感操作
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟根据反序列化数据生成权限
            if (level > 99) {
                permissions = new String[]{"admin", "debug"};
            }
        }
    }
}