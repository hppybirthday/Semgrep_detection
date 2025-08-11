import com.alibaba.fastjson.JSON;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;

// 领域模型：游戏配置
public class GameConfig implements Serializable {
    private String playerName;
    private int difficultyLevel;
    private transient String columnComment; // 敏感字段

    // 领域服务
    public static class ConfigService {
        public GameConfig loadConfig() throws IOException {
            File file = new File("/tmp/object");
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            // 不安全的反序列化操作
            String jsonData = new String(data);
            GameConfig config = JSON.parseObject(jsonData, GameConfig.class);
            
            // 触发潜在漏洞
            if (config.columnComment != null) {
                System.out.println("配置注释: " + config.columnComment);
            }
            
            return config;
        }
    }

    // 领域实体操作
    public static void main(String[] args) {
        try {
            ConfigService service = new ConfigService();
            GameConfig config = service.loadConfig();
            System.out.println("加载配置成功: " + config.playerName);
        } catch (Exception e) {
            System.err.println("配置加载失败: " + e.getMessage());
        }
    }

    // Getters/Setters
    public String getPlayerName() { return playerName; }
    public void setPlayerName(String playerName) { this.playerName = playerName; }
    public int getDifficultyLevel() { return difficultyLevel; }
    public void setDifficultyLevel(int difficultyLevel) { this.difficultyLevel = difficultyLevel; }
    public String getColumnComment() { return columnComment; }
    public void setColumnComment(String columnComment) { this.columnComment = columnComment; }
}