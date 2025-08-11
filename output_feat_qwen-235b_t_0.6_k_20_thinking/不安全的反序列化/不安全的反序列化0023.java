import com.alibaba.fastjson.JSON;
import java.io.IOException;
import java.util.Map;

// 模拟Redis客户端
class RedisClient {
    public byte[] getGameData(String key) {
        // 模拟从Redis获取恶意序列化数据
        return getMaliciousPayload().getBytes();
    }

    private String getMaliciousPayload() {
        // 实际攻击中可能包含FastJSON gadget链
        // 示例payload（简化表示）：
        return "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\","
            + "\\"_bytecodes\\":\\"[恶意字节码]\\",\\"_name\\":\\"a\\",\\"_tfactory\\":{}}";
    }
}

// 游戏配置类
class SystemConfig {
    // 模拟配置更新方法（存在漏洞）
    public void updateConfigs(byte[] data) {
        try {
            // 危险操作：直接反序列化不可信数据
            Object obj = JSON.parse(data);
            if (obj instanceof Map) {
                Map<String, Object> configMap = (Map<String, Object>) obj;
                // 模拟处理配置
                System.out.println("Loaded config: " + configMap.get("version"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 游戏服务器主类
public class GameServer {
    private RedisClient redis = new RedisClient();
    private SystemConfig config = new SystemConfig();

    public void start() {
        System.out.println("Starting game server...");
        
        // 加载配置（触发漏洞）
        String configKey = "game:config:2023";
        byte[] rawData = redis.getGameData(configKey);
        
        if (rawData != null) {
            config.updateConfigs(rawData);
        }
        
        System.out.println("Server started!");
    }

    // 模拟游戏服务器启动
    public static void main(String[] args) {
        GameServer server = new GameServer();
        server.start();
    }
}