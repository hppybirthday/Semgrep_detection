import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

// 数学模型服务类
class MathModelService {
    private String modelName;
    private Map<String, String> config = new HashMap<>();

    public MathModelService(String modelName) {
        this.modelName = modelName;
        // 模拟从远程加载配置
        config.put("default_dataset", "https://example.com/datasets/sample.csv");
    }

    // 存在漏洞的URL处理方法
    public String fetchExternalData(String requestUrl) throws IOException, URISyntaxException {
        // 漏洞点：直接使用用户输入构造URI
        URI uri = new URI(requestUrl);
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        StringBuilder response = new StringBuilder();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
        }
        return response.toString();
    }

    // 模拟模型训练方法
    public String trainModel(String datasetUrl) throws Exception {
        String rawData = fetchExternalData(datasetUrl);
        // 模拟数据处理
        return String.format("Model %s trained with %d bytes of data", 
            modelName, rawData.length());
    }
}

// 仿真控制器类
class SimulationController {
    private MathModelService modelService;

    public SimulationController() {
        modelService = new MathModelService("MonteCarloSimulator");
    }

    // 处理GET请求的模拟方法
    public String handleGetRequest(Map<String, String> params) {
        try {
            String requestUrl = params.getOrDefault("requestUrl", 
                modelService.config.get("default_dataset"));
            return modelService.trainModel(requestUrl);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 模拟Web服务器处理
public class SSRFExample {
    public static void main(String[] args) {
        SimulationController controller = new SimulationController();
        
        // 模拟用户请求
        Map<String, String> params = new HashMap<>();
        params.put("requestUrl", "http://169.254.169.254/latest/meta-data/instance-id");
        
        String response = controller.handleGetRequest(params);
        System.out.println(response);
    }
}