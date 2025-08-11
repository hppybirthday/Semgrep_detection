import com.alibaba.fastjson.JSON;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.util.Map;

public class ChatServer {
    static class ConfigMap {
        String[] users;
        Map<String, String> settings;
    }

    public static void main(String[] args) throws Exception {
        SystemConfig.updateConfigs();
    }

    static class SystemConfig {
        static void updateConfigs() throws Exception {
            FileInputStream fis = new FileInputStream("/tmp/object");
            byte[] data = new byte[fis.available()];
            fis.read(data);
            
            // 漏洞点：使用FastJSON反序列化不可信数据
            ConfigMap config = JSON.parseObject(
                new String(data),
                ConfigMap.class
            );
            
            System.out.println("Loaded config: " + config.settings);
        }
    }

    // 恶意类示例（实际攻击中可能通过其他方式注入）
    static class MaliciousPayload {
        public MaliciousPayload() {
            try {
                Runtime.getRuntime().exec("calc");
            } catch (Exception e) {}
        }
    }
}