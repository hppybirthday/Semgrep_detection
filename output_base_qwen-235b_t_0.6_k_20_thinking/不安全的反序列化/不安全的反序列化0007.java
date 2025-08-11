package com.game.core.settings;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

// 领域模型：游戏设置
public class GameSettings implements Serializable {
    private static final long serialVersionUID = 1L;
    private String playerName;
    private int difficultyLevel;
    private Map<String, Object> customProperties = new HashMap<>();

    public GameSettings(String playerName, int difficultyLevel) {
        this.playerName = playerName;
        this.difficultyLevel = difficultyLevel;
    }

    // 模拟游戏逻辑方法
    public void applySettings() {
        System.out.println("Applying settings for " + playerName + ", difficulty: " + difficultyLevel);
    }

    // 不安全的反序列化实现
    public static GameSettings loadSettings(String filePath) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 漏洞点：直接反序列化不可信数据
            return (GameSettings) ois.readObject();
        }
    }

    // 安全版本应使用白名单验证
    /*
    public static GameSettings safeLoadSettings(String filePath) throws Exception {
        try (ObjectInputStream ois = new FilteringObjectInputStream(new FileInputStream(filePath))) {
            return (GameSettings) ois.readObject();
        }
    }
    */

    // 模拟攻击者构造的恶意类
    /*
    private static class MaliciousPayload implements Serializable {
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            Runtime.getRuntime().exec("calc"); // 模拟RCE攻击
        }
    }
    */

    public static void main(String[] args) {
        try {
            // 模拟正常保存流程
            GameSettings settings = new GameSettings("PlayerOne", 3);
            settings.customProperties.put("uiTheme", "dark");
            
            // 保存设置（正常流程）
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("game.save"))) {
                oos.writeObject(settings);
            }
            
            // 加载设置（存在漏洞）
            GameSettings loaded = GameSettings.loadSettings("game.save");
            loaded.applySettings();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 领域服务层
class GameService {
    private GameSettingsRepository settingsRepo;

    public GameService(GameSettingsRepository settingsRepo) {
        this.settingsRepo = settingsRepo;
    }

    public void importSettings(String filePath) {
        try {
            // 直接使用存在漏洞的反序列化方法
            GameSettings imported = GameSettings.loadSettings(filePath);
            settingsRepo.save(imported);
        } catch (Exception e) {
            System.err.println("Failed to import settings: " + e.getMessage());
        }
    }
}

// 基础设施层接口
interface GameSettingsRepository {
    void save(GameSettings settings);
    GameSettings load();
}