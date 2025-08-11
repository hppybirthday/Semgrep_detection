import java.io.*;
import java.util.ArrayList;

// 玩家类（可序列化）
class Player implements Serializable {
    private String name;
    private int score;
    
    public Player(String name, int score) {
        this.name = name;
        this.score = score;
    }
    
    @Override
    public String toString() {
        return "Player{name='" + name + "', score=" + score + "}";
    }
}

// 游戏状态类（可序列化）
class GameState implements Serializable {
    private ArrayList<Player> players;
    private int currentLevel;
    
    public GameState(ArrayList<Player> players, int currentLevel) {
        this.players = players;
        this.currentLevel = currentLevel;
    }
    
    @Override
    public String toString() {
        return "GameState{players=" + players + ", currentLevel=" + currentLevel + "}";
    }
}

// 游戏保存管理类
class GameSave implements Serializable {
    private GameState state;
    private String saveName;
    
    public GameSave(GameState state, String saveName) {
        this.state = state;
        this.saveName = saveName;
    }
    
    // 模拟加载游戏的错误实现
    public static GameSave loadGame(String filename) {
        try (FileInputStream fis = new FileInputStream(filename);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            
            // 不安全的反序列化操作
            return (GameSave) ois.readObject();
            
        } catch (Exception e) {
            System.out.println("加载失败: " + e.getMessage());
            return null;
        }
    }
    
    @Override
    public String toString() {
        return "GameSave{saveName='" + saveName + "', state=" + state + "}";
    }
}

// 恶意类示例（攻击者构造）
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟执行任意代码（真实攻击中可能是下载木马等操作）
        Runtime.getRuntime().exec("calc"); // 弹出计算器作为演示
    }
}

// 主程序类
public class GameLoader {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请提供保存文件路径");
            return;
        }
        
        String filename = args[0];
        GameSave save = GameSave.loadGame(filename);
        
        if (save != null) {
            System.out.println("游戏加载成功: " + save);
        } else {
            System.out.println("游戏加载失败");
        }
    }
}