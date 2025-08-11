import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

// 高抽象建模：大数据任务执行框架
interface TaskExecutor {
    void executeTask(String dataset) throws IOException;
}

class HadoopJobExecutor implements TaskExecutor {
    @Override
    public void executeTask(String dataset) throws IOException {
        // 漏洞触发点：将用户输入直接拼接到系统命令中
        List<String> command = new ArrayList<>();
        command.add("cmd.exe");
        command.add("/c");
        command.add("hadoop-processing.bat");
        command.add(dataset); // 未过滤的参数注入

        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        // 输出命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("Output: " + line);
        }
    }
}

// 任务调度服务
class TaskScheduler {
    private TaskExecutor executor;

    public TaskScheduler(TaskExecutor executor) {
        this.executor = executor;
    }

    // Web控制器层接口（模拟）
    public void handleWebRequest(String datasetParam) {
        try {
            executor.executeTask(datasetParam);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 模拟入口点（Web控制器）
public class CommandInjectionDemo {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java CommandInjectionDemo <dataset>");
            return;
        }
        
        // 高抽象建模：任务调度流程
        TaskExecutor executor = new HadoopJobExecutor();
        TaskScheduler scheduler = new TaskScheduler(executor);
        
        // 模拟处理用户输入的Web请求
        System.out.println("Processing dataset: " + args[0]);
        scheduler.handleWebRequest(args[0]);
    }
}