import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

// 高抽象建模风格：通过接口抽象游戏核心组件
interface GameComponent {
    void process();
}

// 游戏状态数据模型（存在可变行为）
abstract class PlayerState implements Serializable {
    public abstract void applyEffect();
}

// 具体玩家数据类（包含敏感操作）
class PlayerData extends PlayerState {
    private String playerName;
    private transient Map<String, Object> attributes = new HashMap<>();

    public PlayerData() {}

    public PlayerData(String name) {
        this.playerName = name;
    }

    @Override
    public void applyEffect() {
        System.out.println("Player " + playerName + " applying effects...");
    }

    // 模拟敏感操作
    public void saveProgress() {
        System.out.println("Critical operation: Saving player progress to disk");
    }
}

// 模拟混合缓存系统
class RedisAndLocalCache {
    // 模拟Redis缓存获取（存在不安全反序列化）
    public static Object get(String key) {
        // 模拟从Redis获取的恶意字节流
        byte[] maliciousData = Base64.getDecoder().decode("rO0ABXNyACRqYXZhLnV0aWwuSGFzaG1hcCUZ2uHHXc3wSwIAAkYAC2xvYWRGYWN0b3J5dAAMTGl0ZXJhbHMAAAp0YWJsZUl0ZXJhdG9yAQAAeHB3CAAAAHg=");
        
        // 不安全的反序列化操作（禁用安全防护）
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        return JSON.parseObject(maliciousData, Object.class);
    }
}

// 核心游戏服务类
class GameService implements GameComponent {
    @Override
    public void process() {
        // 模拟从缓存加载玩家数据
        try {
            // 危险的反序列化调用链
            Object cached = RedisAndLocalCache.get("player_data");
            if (cached instanceof PlayerState) {
                ((PlayerState) cached).applyEffect();
            }
        } catch (Exception e) {
            System.err.println("Unexpected error during deserialization: " + e);
        }
    }
}

// 桌面游戏主类
public class DesktopGame {
    public static void main(String[] args) {
        // 初始化游戏服务
        GameComponent game = new GameService();
        
        // 触发存在漏洞的反序列化操作
        System.out.println("[INFO] Loading game data...");
        game.process();
        
        System.out.println("[INFO] Game started successfully");
    }
}