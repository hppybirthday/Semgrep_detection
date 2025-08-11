import java.io.*;
import java.lang.reflect.*;
import java.util.*;

// 游戏行为接口（支持序列化）
interface GameAction extends Serializable {
    void execute();
}

// 玩家数据类
class Player implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private transient String statusMessage;
    private GameAction action;

    public Player(String username, GameAction action) {
        this.username = username;
        this.action = action;
        this.statusMessage = "Active";
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        System.out.println("[DEBUG] Player data reloaded for " + username);
    }
}

// 游戏启动器
class GameLauncher {
    public static void main(String[] args) {
        String saveFile = "player.save";
        
        // 模拟正常存档生成
        generateSafeSave(saveFile);
        
        try {
            // 危险的反序列化操作
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(saveFile));
            Player player = (Player) ois.readObject();
            ois.close();
            
            // 触发潜在攻击面
            System.out.println("Welcome back, " + player.username);
            player.action.execute();  // 接口方法调用构成攻击入口
            
        } catch (Exception e) {
            System.err.println("Load error: " + e.getMessage());
        }
    }

    // 生成正常存档文件
    private static void generateSafeSave(String filename) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename));
            GameAction safeAction = (GameAction) Proxy.newProxyInstance(
                GameAction.class.getClassLoader(),
                new Class<?>[]{GameAction.class},
                (proxy, method, args) -> {
                    System.out.println("Normal game action triggered");
                    return null;
                }
            );
            oos.writeObject(new Player("DefaultUser", safeAction));
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}