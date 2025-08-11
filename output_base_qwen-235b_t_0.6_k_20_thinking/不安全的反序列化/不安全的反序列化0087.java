import java.io.*;
import java.util.*;

// 领域模型：玩家
class Player implements Serializable {
    private String name;
    private int score;
    
    public Player(String name, int score) {
        this.name = name;
        this.score = score;
    }
    
    public void cheat() {
        score += 1000; // 外挂修改分数
    }
    
    @Override
    public String toString() {
        return "Player{name='" + name + "', score=" + score + "}";
    }
}

// 领域服务：游戏会话
class GameSession implements Serializable {
    private Player currentPlayer;
    private List<String> achievements = new ArrayList<>();
    
    public GameSession(Player player) {
        this.currentPlayer = player;
    }
    
    public void addAchievement(String achievement) {
        achievements.add(achievement);
    }
    
    @Override
    public String toString() {
        return "GameSession{player=" + currentPlayer + ", achievements=" + achievements + "}";
    }
}

// 应用服务：游戏存档管理
class GameSaver {
    // 不安全的反序列化漏洞点
    public static GameSession loadGame(String filename) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            // 直接反序列化不可信数据
            return (GameSession) ois.readObject();
        }
    }
    
    public static void saveGame(GameSession session, String filename) throws Exception {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(session);
        }
    }
}

// 恶意类示例（攻击者可构造）
class MaliciousPlayer extends Player {
    public MaliciousPlayer() {
        super("Hacker", 0);
    }
    
    private void execCommand() {
        try {
            // 实际攻击可能执行任意命令
            Runtime.getRuntime().exec("calc"); // 示例：弹出计算器
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        execCommand(); // 反序列化时自动触发
    }
}

public class DesktopGame {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java DesktopGame <filename>");
            return;
        }
        
        try {
            // 模拟从存档加载游戏
            GameSession session = GameSaver.loadGame(args[0]);
            System.out.println("Loaded session: " + session);
            
            // 正常游戏逻辑
            session.addAchievement("First Launch");
            System.out.println("Updated session: " + session);
            
        } catch (Exception e) {
            System.err.println("Failed to load game: " + e.getMessage());
            e.printStackTrace();
        }
    }
}