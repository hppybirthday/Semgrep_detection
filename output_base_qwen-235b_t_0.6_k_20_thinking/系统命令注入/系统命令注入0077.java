import java.io.*;
import java.util.*;

// 领域模型：数学仿真任务
class Simulation {
    private String name;
    private String parameters;

    public Simulation(String name, String parameters) {
        this.name = name;
        this.parameters = parameters;
    }

    public String getName() { return name; }
    public String getParameters() { return parameters; }
}

// 仓储接口
interface SimulationRepository {
    void runSimulation(Simulation simulation) throws IOException;
}

// 带漏洞的实现类
class VulnerableSimulationRepo implements SimulationRepository {
    @Override
    public void runSimulation(Simulation simulation) throws IOException {
        // 漏洞点：直接拼接用户输入
        String command = "python3 /scripts/" + simulation.getName() + ".py " + simulation.getParameters();
        
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}

// 领域服务
class SimulationService {
    private SimulationRepository repo;

    public SimulationService(SimulationRepository repo) {
        this.repo = repo;
    }

    public void executeSimulation(Simulation simulation) throws IOException {
        repo.runSimulation(simulation);
    }
}

// 应用入口
public class SimulationApplication {
    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.out.println("Usage: java SimulationApplication <script_name> <parameters>");
            return;
        }

        Simulation simulation = new Simulation(args[0], args[1]);
        SimulationService service = new SimulationService(new VulnerableSimulationRepo());
        
        System.out.println("Running simulation...");
        service.executeSimulation(simulation);
    }
}