import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// 命令执行接口
interface CommandExecutor {
    String execute(String command) throws IOException;
}

// Python脚本执行器
class PythonScriptExecutor implements CommandExecutor {
    @Override
    public String execute(String scriptName) throws IOException {
        // 漏洞点：直接拼接用户输入到系统命令中
        Process process = Runtime.getRuntime().exec("python3 " + scriptName);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(process.getErrorStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        while ((line = errorReader.readLine()) != null) {
            output.append("[ERROR] ").append(line).append("\
");
        }
        return output.toString();
    }
}

// 数学模型服务层
class MathModelService {
    private CommandExecutor executor;

    public MathModelService(CommandExecutor executor) {
        this.executor = executor;
    }

    public String runSimulation(String scriptName) throws IOException {
        // 执行用户提供的Python脚本进行数学计算
        return executor.execute(scriptName);
    }
}

// Web控制器层
class SimulationController {
    private MathModelService service;

    public SimulationController(MathModelService service) {
        this.service = service;
    }

    // 模拟HTTP请求处理
    public void handleRequest(String scriptName) {
        try {
            System.out.println("执行结果：\
" + service.runSimulation(scriptName));
        } catch (Exception e) {
            System.err.println("执行失败: " + e.getMessage());
        }
    }
}

// 主程序入口
public class Main {
    public static void main(String[] args) {
        // 模拟Web请求参数注入
        String userInput = args.length > 0 ? args[0] : "example_script.py";
        
        // 构造安全的执行器（本应使用参数化方式）
        CommandExecutor executor = new PythonScriptExecutor();
        MathModelService service = new MathModelService(executor);
        SimulationController controller = new SimulationController(service);
        
        // 触发漏洞
        controller.handleRequest(userInput);
    }
}