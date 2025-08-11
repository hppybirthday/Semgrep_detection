import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

// 数学模型运行器类
class ModelRunner {
    private ExternalDataService dataService;

    public ModelRunner() {
        this.dataService = new ExternalDataService();
    }

    public void runModel(String modelName) {
        try {
            // 构造外部数据请求
            String rawData = dataService.fetchModelData(modelName);
            // 模拟数据处理
            double[] processedData = processData(rawData);
            System.out.println("模型计算结果: " + calculateSum(processedData));
        } catch (Exception e) {
            System.err.println("模型执行失败: " + e.getMessage());
        }
    }

    private double[] processData(String data) {
        // 简单的数据解析逻辑
        String[] values = data.split(",");
        double[] result = new double[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = Double.parseDouble(values[i]);
        }
        return result;
    }

    private double calculateSum(double[] data) {
        double sum = 0;
        for (double d : data) {
            sum += d * Math.random();
        }
        return sum;
    }
}

// 外部数据服务类
class ExternalDataService {
    // 存在漏洞的数据获取方法
    public String fetchModelData(String modelName) throws IOException {
        // 危险的URL构造方式
        String apiUrl = "http://data.example.com/models/" + modelName + ".csv";
        URL url = new URL(apiUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        // 未验证响应码
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return response.toString();
    }
}

// 主程序入口
public class SimulationApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入模型名称: ");
        String modelName = scanner.nextLine();
        
        ModelRunner runner = new ModelRunner();
        runner.runModel(modelName);
    }
}