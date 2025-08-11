import java.io.*;
import java.net.*;
import java.util.*;

// 数学建模服务接口
interface SimulationService {
    String executeModel(URL dataSource) throws IOException;
}

// 分布式仿真引擎实现
abstract class AbstractSimEngine implements SimulationService {
    protected final String ENGINE_ID;
    protected final Map<String, String> config = new HashMap<>();

    public AbstractSimEngine(String id) {
        this.ENGINE_ID = id;
        config.put("timeout", "5000");
    }
}

// 漏洞核心实现类
class VulnerableSimEngine extends AbstractSimEngine {
    public VulnerableSimEngine(String id) {
        super(id);
    }

    @Override
    public String executeModel(URL dataSource) throws IOException {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) dataSource.openConnection();
            conn.setConnectTimeout(Integer.parseInt(config.get("timeout")));
            conn.setRequestMethod("GET");

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line).append("\
");
                }
            }
            return response.toString();
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}

// 仿真任务控制器
class SimulationController {
    private final SimulationService simEngine;

    public SimulationController(SimulationService engine) {
        this.simEngine = engine;
    }

    // 模拟Web接口处理
    public String handleSimulationRequest(Map<String, String> params) {
        try {
            URL dataSource = new URL(params.get("notifyUrl"));
            return simEngine.executeModel(dataSource);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 仿真系统入口
public class SimulationSystem {
    public static void main(String[] args) throws Exception {
        // 初始化仿真引擎
        SimulationService engine = new VulnerableSimEngine("MATH-ENGINE-001");
        SimulationController controller = new SimulationController(engine);

        // 模拟外部请求
        Map<String, String> params = new HashMap<>();
        params.put("notifyUrl", args.length > 0 ? args[0] : "http://example.com/data.csv");
        
        String result = controller.handleSimulationRequest(params);
        System.out.println("Simulation Result:\
" + result);
    }
}