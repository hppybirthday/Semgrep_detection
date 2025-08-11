import java.io.*;
import java.util.Scanner;

// 数学模型仿真主类
public class MathModelSimulator {
    public static void main(String[] args) {
        System.out.println("=== 数学建模与仿真系统 ===");
        SimulationExecutor executor = new SimulationExecutor();
        
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入仿真参数(例如\\"-t 10 -s 0.5\\")：");
        String params = scanner.nextLine();
        
        try {
            System.out.println("开始执行仿真...");
            String result = executor.runSimulation(params);
            System.out.println("仿真结果：\
" + result);
        } catch (Exception e) {
            System.err.println("执行失败：" + e.getMessage());
        }
    }
}

// 仿真执行器类
class SimulationExecutor {
    // 模拟调用外部计算工具的漏洞方法
    public String runSimulation(String parameters) throws IOException, InterruptedException {
        // 漏洞点：直接拼接用户输入到系统命令
        String command = "python3 /opt/simulation_engine.py " + parameters;
        
        System.out.println("执行命令：" + command);
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("仿真进程异常退出，代码：" + exitCode);
        }
        
        return output.toString();
    }
}