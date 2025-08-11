import java.io.*;

class SimulationManager {
    private CommandExecutor executor;

    public SimulationManager() {
        this.executor = new CommandExecutor();
    }

    public String runSimulation(String modelParams) {
        String scriptPath = "/usr/local/bin/run_model.sh";
        return executor.executeCommand(scriptPath, modelParams);
    }
}

class CommandExecutor {
    public String executeCommand(String scriptPath, String params) {
        StringBuilder output = new StringBuilder();
        
        try {
            // 漏洞点：直接拼接用户参数到命令字符串
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", scriptPath + " " + params}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            process.waitFor();
            
        } catch (Exception e) {
            output.append("Error: ").append(e.getMessage());
        }
        
        return output.toString();
    }
}

class UserInputHandler {
    // 模拟从外部获取不可信输入
    public static String getUnsafeInput(String[] args) {
        if (args.length > 0) {
            return args[0]; // 直接返回用户输入
        }
        return "default_params";
    }
}

public class ModelSimulator {
    public static void main(String[] args) {
        SimulationManager manager = new SimulationManager();
        String userInput = UserInputHandler.getUnsafeInput(args);
        
        // 执行存在漏洞的命令调用
        String result = manager.runSimulation(userInput);
        System.out.println("Simulation Result:\
" + result);
    }
}