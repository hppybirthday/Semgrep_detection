import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 数学建模仿真系统核心执行器
 * 模拟调用外部计算工具时的命令注入漏洞
 */
public class SimulationExecutor {
    
    /**
     * 执行数学建模计算任务
     * @param modelParams 用户输入的模型参数（存在漏洞的参数）
     * @return 计算结果输出
     * @throws IOException
     */
    public String executeSimulation(String modelParams) throws IOException {
        // 模拟调用外部计算工具（存在漏洞的实现）
        String command = "python /opt/math_engine.py -params " + modelParams;
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取计算结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}

/**
 * 模型运行器类（面向对象设计）
 */
class ModelRunner {
    private SimulationExecutor executor;
    
    public ModelRunner() {
        this.executor = new SimulationExecutor();
    }
    
    /**
     * 运行数学建模任务
     * @param userInput 用户输入参数
     * @throws IOException
     */
    public void runModel(String userInput) throws IOException {
        System.out.println("[执行结果]: " + executor.executeSimulation(userInput));
    }
}

/**
 * 模拟客户端代码
 */
public class SimulationClient {
    public static void main(String[] args) {
        // 模拟用户输入（攻击者可注入命令）
        String userInput = "base_model --precision high; rm -rf /tmp/*";
        
        ModelRunner runner = new ModelRunner();
        try {
            System.out.println("开始执行数学建模任务...");
            runner.runModel(userInput);
            System.out.println("任务完成");
        } catch (IOException e) {
            System.err.println("执行错误: " + e.getMessage());
        }
    }
}