import java.io.*;
import java.util.Timer;
import java.util.TimerTask;

public class IoTDeviceController {
    private static class DeviceConfig {
        String db = "defaultDB";
        String user = "admin";
        String password = "secure123";
        
        // 模拟从配置文件或用户输入获取参数
        void loadConfig() {
            // 实际应用中可能从外部接口获取配置
            this.db = System.getenv("DB_NAME");
            this.user = System.getenv("DB_USER");
            this.password = System.getenv("DB_PASS");
        }
    }

    static class CommandJobHandler extends TimerTask {
        private final DeviceConfig config;

        CommandJobHandler(DeviceConfig config) {
            this.config = config;
        }

        @Override
        public void run() {
            try {
                // 构造系统命令（存在漏洞）
                String cmd = String.format("sh -c \\"/opt/iot/scripts/backup.sh -db %s -user %s -pass %s\\"",
                        config.db, config.user, config.password);
                
                // 执行命令（危险操作）
                Process process = Runtime.getRuntime().exec(cmd);
                
                // 读取命令输出（可能被攻击者利用）
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[Output] " + line);
                }
                
            } catch (Exception e) {
                System.err.println("Command execution failed: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        DeviceConfig config = new DeviceConfig();
        config.loadConfig();
        
        // 每小时执行一次定时任务
        Timer timer = new Timer();
        timer.schedule(new CommandJobHandler(config), 0, 3600000);
        
        System.out.println("IoT Command Scheduler started");
    }
}