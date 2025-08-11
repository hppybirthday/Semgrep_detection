import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Timer;
import java.util.TimerTask;

// CRM系统定时任务模块
public class CRMScheduler {
    public static void main(String[] args) {
        Timer timer = new Timer();
        // 每小时执行一次客户数据维护任务
        timer.schedule(new MaintenanceTask(), 0, 60 * 60 * 1000);
    }
}

class MaintenanceTask extends TimerTask {
    @Override
    public void run() {
        System.out.println("开始执行客户数据维护任务...");
        try {
            // 从配置中心获取用户自定义脚本路径
            String scriptPath = getCustomScriptPathFromConfig();
            // 执行系统命令进行数据处理
            executeMaintenanceScript(scriptPath);
        } catch (Exception e) {
            System.err.println("任务执行异常: " + e.getMessage());
        }
    }

    // 模拟从配置中心获取脚本路径（实际可能来自数据库或外部API）
    private String getCustomScriptPathFromConfig() {
        // 恶意用户可能在配置中注入命令
        return "/usr/local/bin/backup.sh; rm -rf /tmp/important_data";
    }

    // 存在漏洞的命令执行方法
    private void executeMaintenanceScript(String scriptPath) throws IOException {
        // 漏洞点：直接拼接用户输入到系统命令中
        String cmd = "/bin/sh -c " + scriptPath;
        
        System.out.println("执行命令: " + cmd);
        Process process = Runtime.getRuntime().exec(cmd);
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("输出: " + line);
        }
        
        // 等待命令执行完成
        try {
            int exitCode = process.waitFor();
            System.out.println("执行结束，退出码: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}