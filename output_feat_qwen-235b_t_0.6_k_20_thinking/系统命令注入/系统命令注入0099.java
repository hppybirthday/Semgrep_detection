import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

// 模拟HTTP请求参数处理类
class HttpServletRequest {
    private final String cmdParam;

    public HttpServletRequest(String cmdParam) {
        this.cmdParam = cmdParam;
    }

    public String getParameter(String name) {
        return name.equals("cmd_") ? cmdParam : null;
    }
}

// 任务接口定义
interface Task {
    void execute() throws IOException;
}

// 命令任务实现
class CommandTask implements Task {
    private final String[] commandTemplate;
    private final String userParam;

    public CommandTask(String[] commandTemplate, String userParam) {
        this.commandTemplate = commandTemplate;
        this.userParam = userParam;
    }

    @Override
    public void execute() throws IOException {
        List<String> command = new ArrayList<>();
        for (String part : commandTemplate) {
            command.add(part.replace("{PARAM}", userParam));
        }
        
        // 调用系统命令执行（存在漏洞）
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        try {
            int exitCode = process.waitFor();
            System.out.println("Exit code: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Execution interrupted", e);
        }
    }
}

// 任务调度中心
class TaskScheduler {
    public void handleRequest(HttpServletRequest request) {
        String cmdParam = request.getParameter("cmd_");
        
        // 构建带参数的系统命令（存在漏洞）
        String[] commandTemplate = {"/bin/sh", "-c", "echo \\"Executing task: {PARAM}\\" && sleep 1"};
        
        Task task = new CommandTask(commandTemplate, cmdParam);
        try {
            task.execute();
        } catch (IOException e) {
            System.err.println("Task execution failed: " + e.getMessage());
        }
    }
}

// 主程序入口
public class VulnerableTaskManager {
    public static void main(String[] args) {
        // 模拟用户输入（攻击者可控）
        String userInput = args.length > 0 ? args[0] : "default_task";
        
        // 创建模拟HTTP请求
        HttpServletRequest request = new HttpServletRequest(userInput);
        
        // 执行任务调度
        new TaskScheduler().handleRequest(request);
    }
}