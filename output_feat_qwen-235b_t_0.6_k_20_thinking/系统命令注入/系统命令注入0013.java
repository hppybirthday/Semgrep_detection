import java.io.*;
import java.util.Scanner;

public class SimulationController {
    private final ModelSimulator simulator;

    public SimulationController() {
        this.simulator = new ModelSimulator();
    }

    public void startSimulation() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("数学建模仿真系统 v1.0");
        System.out.print("请输入模型名称: ");
        String modelName = scanner.nextLine();
        
        // 构造系统命令（存在漏洞）
        String[] cmd = {"/bin/sh", "-c", "./run_sim.sh " + modelName};
        
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            process.waitFor();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            System.out.println("仿真结果:");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            System.err.println("执行错误: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SimulationController controller = new SimulationController();
        controller.startSimulation();
    }
}

class ModelSimulator {
    // 模拟模型执行器（实际可能调用外部工具）
    public void executeModel(String modelName) {
        System.out.println("正在执行模型: " + modelName);
        // 实际执行可能调用外部脚本/工具
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}