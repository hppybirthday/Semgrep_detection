package com.gamestudio.desktop;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

// 游戏实体基类
abstract class GameEntity implements Serializable {
    protected String name;
    protected int id;

    public GameEntity(String name, int id) {
        this.name = name;
        this.id = id;
    }

    public abstract void update();
}

// 玩家数据类
class PlayerData extends GameEntity {
    private int level;
    private transient String sensitiveData; // 敏感字段应被transient修饰

    public PlayerData(String name, int id, int level) {
        super(name, id);
        this.level = level;
        this.sensitiveData = "bankAccount:123456"; // 模拟敏感信息
    }

    @Override
    public void update() {
        System.out.println("Player " + name + " level up to " + level);
    }
}

// 物品数据类
class ItemData extends GameEntity {
    private String type;

    public ItemData(String name, int id, String type) {
        super(name, id);
        this.type = type;
    }

    @Override
    public void update() {
        System.out.println("Item " + name + " used, type: " + type);
    }
}

// 恶意类（攻击者构造）
class MaliciousPayload extends GameEntity {
    public MaliciousPayload() {
        super("Malicious", 999);
    }

    private void execCommand() {
        try {
            // 模拟执行任意命令
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        execCommand(); // 反序列化时自动触发
    }

    @Override
    public void update() {}
}

// 存档管理器
class SaveGameManager {
    private static final String SAVE_DIR = "./saves/";

    // 保存游戏状态（存在漏洞的序列化）
    public static void saveGame(GameEntity entity, String filename) throws IOException {
        try (ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream(SAVE_DIR + filename))) {
            out.writeObject(entity);
        }
    }

    // 加载游戏存档（存在漏洞的反序列化）
    public static GameEntity loadGame(String filename) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(
                new FileInputStream(SAVE_DIR + filename))) {
            return (GameEntity) in.readObject(); // 危险的反序列化操作
        }
    }
}

// 游戏主类
public class UnsafeDeserializationGame {
    public static void main(String[] args) {
        try {
            // 创建存档目录
            new File(SaveGameManager.SAVE_DIR).mkdirs();

            // 正常存档示例
            PlayerData player = new PlayerData("Hero", 1, 10);
            SaveGameManager.saveGame(player, "player.save");

            // 加载正常存档
            GameEntity loaded = SaveGameManager.loadGame("player.save");
            loaded.update();

            // 恶意攻击演示（模拟攻击者构造的文件）
            System.out.println("\
[模拟攻击者尝试注入恶意代码]");
            MaliciousPayload payload = new MaliciousPayload();
            SaveGameManager.saveGame(payload, "malicious.save");

            // 加载恶意存档时触发漏洞
            System.out.println("加载恶意存档...");
            GameEntity evil = SaveGameManager.loadGame("malicious.save");
            evil.update();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}