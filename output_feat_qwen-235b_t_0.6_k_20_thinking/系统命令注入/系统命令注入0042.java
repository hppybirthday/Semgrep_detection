import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class DataCleaner {
    public static void main(String[] args) {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        
        // 模拟用户配置参数（实际可能来自配置文件或API）
        String cleanupPath = System.getenv("CLEANUP_PATH");
        
        // 每天凌晨2点执行清理任务
        scheduler.scheduleAtFixedRate(
            createCleanupTask(cleanupPath),
            getInitialDelay(),
            TimeUnit.DAYS.toMillis(1),
            TimeUnit.MILLISECONDS
        );
    }

    private static long getInitialDelay() {
        // 简化时间计算逻辑
        return 60_000;
    }

    private static Runnable createCleanupTask(String path) {
        return () -> {
            try {
                // 构造危险的shell命令（存在命令注入漏洞）
                String command = "sh -c \\"find " + path + " -type f -name \\"*.tmp\\" -delete\\"";
                
                // 执行命令
                Process process = Runtime.getRuntime().exec(command);
                
                // 读取输出
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
                );
                
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Deleted: " + line);
                }
                
                int exitCode = process.waitFor();
                System.out.println("Cleanup completed with exit code: " + exitCode);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
    }
}