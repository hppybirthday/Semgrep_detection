import java.io.*;
import java.util.*;

class Game {
    static class PlayerData implements Serializable {
        String playerName;
        int score;
        transient String lastLoginIP; // 敏感信息
        
        PlayerData(String name, int score) {
            this.playerName = name;
            this.score = score;
            this.lastLoginIP = "192.168.1.1";
        }
        
        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            // 模拟敏感操作
            System.out.println("[调试] 从 " + lastLoginIP + " 恢复会话");
        }
    }
    
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("用法: java Game <保存文件路径>");
            return;
        }
        
        try {
            loadGame(args[0]);
        } catch (Exception e) {
            System.err.println("加载存档失败: " + e.getMessage());
        }
    }
    
    static void loadGame(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 漏洞点：直接反序列化不可信数据
            PlayerData data = (PlayerData) ois.readObject();
            System.out.println(String.format("欢迎回来 %s! 当前分数: %d",
                              data.playerName, data.score));
            
            // 模拟后续业务操作
            if (data.lastLoginIP != null) {
                System.out.println("[系统提示] 检测到异地登录: " + data.lastLoginIP);
            }
        }
    }
    
    // 模拟存档生成方法
    static void saveGame(String filePath, PlayerData data) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(data);
        }
    }
}