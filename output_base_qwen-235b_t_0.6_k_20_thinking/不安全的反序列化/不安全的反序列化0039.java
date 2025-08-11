import java.io.*;
import java.util.*;

// 高抽象建模风格接口设计
interface GameState extends Serializable {
    void restore();
    void save();
}

// 具体游戏状态实现
class GameSnapshot implements GameState {
    private final Player player;
    private final Board board;
    
    public GameSnapshot(Player player, Board board) {
        this.player = player;
        this.board = board;
    }
    
    @Override
    public void restore() {
        System.out.println("[游戏恢复] 玩家位置: " + player.getPosition() + ", 棋盘状态: " + board.getHash());
    }
    
    @Override
    public void save() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("save.dat"))) {
            oos.writeObject(this);
            System.out.println("游戏已保存到save.dat");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 游戏实体类
class Player implements Serializable {
    private String name;
    private Point position;
    
    public Player(String name, int x, int y) {
        this.name = name;
        this.position = new Point(x, y);
    }
    
    public Point getPosition() {
        return position;
    }
}

class Board implements Serializable {
    private final int[][] grid;
    
    public Board(int size) {
        this.grid = new int[size][size];
        // 初始化随机棋盘
        for(int i=0; i<size; i++) {
            for(int j=0; j<size; j++) {
                grid[i][j] = (int)(Math.random()*10);
            }
        }
    }
    
    public String getHash() {
        return Integer.toHexString(Arrays.deepHashCode(grid));
    }
}

// 不安全的反序列化操作
class GameLoader {
    public static GameState loadGame() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("save.dat"))) {
            // 脆弱点：直接反序列化未经验证的对象
            return (GameState) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

// 恶意类示例（攻击者可构造的恶意序列化对象）
class MaliciousPayload implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 模拟攻击载荷
        Runtime.getRuntime().exec("calc.exe"); // 模拟任意代码执行
    }
}

// 游戏入口点
public class DesktopGame {
    public static void main(String[] args) {
        // 正常游戏流程
        Player player = new Player("Hero", 10, 20);
        Board board = new Board(5);
        
        // 保存游戏状态
        GameSnapshot snapshot = new GameSnapshot(player, board);
        snapshot.save();
        
        // 加载游戏状态（存在漏洞）
        GameState loadedState = GameLoader.loadGame();
        if(loadedState != null) {
            loadedState.restore();
        }
    }
}