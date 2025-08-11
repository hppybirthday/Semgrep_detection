import java.io.*;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@SpringBootApplication
public class SimulationApplication {
    public static void main(String[] args) {
        SpringApplication.run(SimulationApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class SimulationController {
    private final SimulationService simulationService = new SimulationService();

    @GetMapping("/run")
    public String runSimulation(@RequestParam String dataSource, @RequestParam String modelType) {
        try {
            // 元编程风格：通过反射动态调用模型处理方法
            String result = simulationService.process(dataSource, modelType);
            return "Model output: " + result.substring(0, Math.min(60, result.length())) + "...";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class SimulationService {
    private final Map<String, Function<String, String>> modelHandlers = new HashMap<>();

    public SimulationService() {
        // 元编程：初始化内置模型处理器
        modelHandlers.put("linear", this::processLinearModel);
        modelHandlers.put("exponential", this::processExponentialModel);
    }

    public String process(String dataSource, String modelType) throws Exception {
        // 漏洞点：直接使用用户输入的URL
        String rawData = fetchData(dataSource);
        
        // 动态调用模型处理方法
        Function<String, String> handler = modelHandlers.getOrDefault(modelType, this::defaultHandler);
        return handler.apply(rawData);
    }

    // 漏洞触发点：未验证的URL访问
    private String fetchData(String dataSource) throws IOException {
        URL url = new URL(dataSource);
        InputStream in = url.openStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\
");
        }
        reader.close();
        return sb.toString();
    }

    // 元编程：通过反射动态执行模型计算
    private String processLinearModel(String data) {
        try {
            Class<?> clazz = Class.forName("com.example.LinearModelCalculator");
            Method method = clazz.getMethod("calculate", String.class);
            return (String) method.invoke(null, data);
        } catch (Exception e) {
            return "Linear model error: " + e.getMessage();
        }
    }

    private String processExponentialModel(String data) {
        // 模拟指数模型处理
        return "Exponential analysis complete. Data length: " + data.length();
    }

    private String defaultHandler(String data) {
        return "Raw data length: " + data.length();
    }
}

// 模拟的数学模型计算类
class LinearModelCalculator {
    public static String calculate(String data) {
        // 实际计算逻辑
        return "Linear result: " + data.hashCode();
    }
}