import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

// 高抽象建模：命令执行策略接口
interface CommandExecutor {
    String execute(String[] params) throws IOException;
}

// 具体策略：存在漏洞的系统命令执行器
class VulnerableSystemExecutor implements CommandExecutor {
    @Override
    public String execute(String[] params) throws IOException {
        // 漏洞点：直接拼接用户输入到命令中
        String cmd = "/bin/sh -c tar -czf /backups/" + params[0] + ".tar.gz /tasks/" + params[0];
        Process process = Runtime.getRuntime().exec(cmd);
        
        // 读取执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\
");
        }
        return result.toString();
    }
}

// 任务管理服务层
class TaskService {
    private CommandExecutor executor;

    public TaskService(CommandExecutor executor) {
        this.executor = executor;
    }

    // 业务方法：备份任务数据
    public String backupTask(String taskId) {
        try {
            return executor.execute(new String[]{taskId});
        } catch (IOException e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

// 模拟HTTP控制器
abstract class BaseController {
    public abstract String handleRequest(String[] params);
}

class TaskController extends BaseController {
    private TaskService taskService;

    public TaskController() {
        this.taskService = new TaskService(new VulnerableSystemExecutor());
    }

    @Override
    public String handleRequest(String[] params) {
        if (params.length == 0) {
            return "Missing task ID";
        }
        // 直接使用未经验证的用户输入
        return taskService.backupTask(params[0]);
    }
}

// 模拟应用入口
public class CommandInjectionDemo {
    public static void main(String[] args) {
        // 模拟HTTP请求处理
        BaseController controller = new TaskController();
        // 恶意输入示例："test; rm -rf / #"
        String[] userInput = {"test; rm -rf / #"};
        System.out.println("模拟请求处理结果:\
" + controller.handleRequest(userInput));
    }
}