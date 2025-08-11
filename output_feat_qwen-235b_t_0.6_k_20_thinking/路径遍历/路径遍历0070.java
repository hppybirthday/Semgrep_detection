import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class IoTDataProcessor {
    // 模拟设备配置
    private static final String BASE_PATH = "/var/iotsystem/data/";
    private static final String LOG_HEADER = "# Device Data Log - Generated on: ";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java IoTDataProcessor <filename>");
            return;
        }

        String userInput = args[0];
        String fullFilePath = generateFilePath(userInput);
        
        try {
            // 生成设备数据
            String dataContent = collectSensorData();
            // 写入文件（包含漏洞的调用）
            GenerateUtil.generateFile(fullFilePath, dataContent);
            System.out.println("Data saved to: " + fullFilePath);
        } catch (IOException e) {
            System.err.println("File operation failed: " + e.getMessage());
        }
    }

    private static String generateFilePath(String userInput) {
        // 路径构造逻辑：基础目录 + 日期子目录 + 用户输入
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/");
        return BASE_PATH + sdf.format(new Date()) + userInput;
    }

    private static String collectSensorData() {
        // 模拟采集温度、湿度等数据
        StringBuilder sb = new StringBuilder();
        sb.append(LOG_HEADER).append(new Date()).append("\
");
        sb.append("Temperature: 23.5°C\
");
        sb.append("Humidity: 45%\
");
        sb.append("Status: OK\
");
        return sb.toString();
    }
}

class GenerateUtil {
    public static void generateFile(String filePath, String content) throws IOException {
        File file = new File(filePath);
        
        // 危险的路径检查逻辑
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }

        // 存在漏洞的文件写入操作
        try (BufferedWriter writer = new BufferedWriter(
             new FileWriter(file))) {
            writer.write(content);
        }
    }
}