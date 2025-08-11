import java.io.*;
import java.util.*;
import java.lang.ProcessBuilder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class MathModelSimulator {
    public static void main(String[] args) {
        SpringApplication.run(MathModelSimulator.class, args);
    }

    @RestController
    public static class SimulationController {
        @PostMapping("/simulate")
        public String runSimulation(@RequestParam String equation) {
            try {
                // 构造存在漏洞的系统命令
                String[] cmd = {"/bin/sh", "-c", "python3 simulate_model.py '" + equation + "'"};
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.redirectErrorStream(true);
                Process process = pb.start();

                // 读取命令执行结果
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
                );
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                return "Simulation Result:\
" + output.toString();

            } catch (Exception e) {
                return "Error executing simulation: " + e.getMessage();
            }
        }

        @GetMapping("/health")
        public String healthCheck() {
            return "Service is running";
        }
    }
}

/*
模拟执行的Python脚本(simulate_model.py)：
import sys, numpy as np
try:
    eq = sys.argv[1]
    # 模拟数学建模计算过程
    result = eval(eq.replace('^','**'))
    print(f"Model output: {result}")
except Exception as e:
    print(f"Execution error: {str(e)}")
*/