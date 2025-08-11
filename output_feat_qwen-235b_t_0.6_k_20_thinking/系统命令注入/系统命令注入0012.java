import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.io.BufferedReader;
import java.io.InputStreamReader;

@FunctionalInterface
interface CommandExecutor {
    void execute(String cmd);
}

public class CRMBackupScheduler {
    
    static class DbUtil {
        static String buildBackupCommand(String user, String password, String db) {
            return "mysqldump -u" + user + " -p" + password + " " + db + " > C:\\\\backup\\\\" + db + "_backup.sql";
        }
    }
    
    static class CommandExecUtil {
        static void execCommand(String command) {
            try {
                ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                
                int exitCode = process.waitFor();
                System.out.println("\
Backup completed with exit code: " + exitCode);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    static class UserInputSource {
        static String[] getBackupParams() {
            // 模拟从配置文件或数据库读取的用户输入
            // 恶意输入示例：用户输入密码为 "pass123&del /Q C:\\\\*"
            return new String[]{
                "admin",  // 用户名
                "securePass123",  // 密码
                "customer_db"  // 数据库名
            };
        }
    }

    public static void main(String[] args) {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        
        Runnable backupTask = () -> {
            String[] params = UserInputSource.getBackupParams();
            String cmd = DbUtil.buildBackupCommand(params[0], params[1], params[2]);
            System.out.println("Executing backup command: " + cmd);
            CommandExecUtil.execCommand(cmd);
        };
        
        // 每天凌晨1点执行备份（简化为10秒间隔演示）
        scheduler.scheduleAtFixedRate(backupTask, 0, 10, TimeUnit.SECONDS);
    }
}