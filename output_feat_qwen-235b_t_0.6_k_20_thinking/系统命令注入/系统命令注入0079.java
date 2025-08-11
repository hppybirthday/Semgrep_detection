import java.io.IOException;

// 定时任务调度接口
interface TaskScheduler {
    void scheduleTask(String[] params);
}

// 云原生微服务组件
class CronTaskScheduler implements TaskScheduler {
    private final CommandExecutor executor;

    public CronTaskScheduler(CommandExecutor executor) {
        this.executor = executor;
    }

    @Override
    public void scheduleTask(String[] params) {
        if (params.length < 1) return;
        
        // 漏洞点：直接拼接用户输入参数构造命令
        String command = "echo \\"Processing log file:\\" " + params[0] + " && cat /var/logs/" + params[0];
        
        try {
            // 模拟K8s环境下的日志处理任务
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 命令执行器
class CommandExecutor {
    public void execute(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }
}

// 微服务启动类
class SchedulerApplication {
    public static void main(String[] args) {
        // 模拟Kubernetes ConfigMap注入参数
        String[] userInput = {"app.log; rm -rf /tmp/* && echo MALICIOUS_CODE_EXECUTED"};
        
        CommandExecutor executor = new CommandExecutor();
        TaskScheduler scheduler = new CronTaskScheduler(executor);
        
        // 触发定时任务
        scheduler.scheduleTask(userInput);
    }
}