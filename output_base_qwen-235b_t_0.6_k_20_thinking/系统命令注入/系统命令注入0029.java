import java.io.*;
import java.util.Scanner;

interface Simulator {
    void runSimulation(String param) throws Exception;
}

abstract class ModelSimulator {
    protected abstract String getScriptPath();
    public void execute(String param) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("python3", getScriptPath(), param);
        Process process = pb.start();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}

class ClimateModel extends ModelSimulator implements Simulator {
    @Override
    protected String getScriptPath() {
        return "climate_simulation.py";
    }

    @Override
    public void runSimulation(String param) throws Exception {
        execute(param);
    }
}

public class SimulationRunner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter simulation parameter (temperature threshold): ");
        String param = scanner.nextLine();
        
        try {
            Simulator simulator = new ClimateModel();
            // 执行气候模型仿真，参数直接传递给Python脚本
            simulator.runSimulation(param);
        } catch (Exception e) {
            System.err.println("Simulation failed: " + e.getMessage());
        }
    }
}

// climate_simulation.py 内容示例：
// import sys
// temp = float(sys.argv[1])
// print(f"Running climate model with threshold: {temp}°C")