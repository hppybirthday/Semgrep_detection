import java.io.*;
import java.util.HashMap;
import java.util.Map;

// 数学模型配置管理器
public class SimulationConfigManager {
    private String uploadPath;
    private Map<String, String> modelSettings;

    public SimulationConfigManager(String baseUploadPath) {
        this.uploadPath = baseUploadPath;
        this.modelSettings = new HashMap<>();
    }

    // 模拟数据生成器
    private static class DataGenerator {
        public String generateSimulationData(int points) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < points; i++) {
                double x = i * 0.1;
                sb.append(x).append(",").append(Math.sin(x)).append("\
");
            }
            return sb.toString();
        }
    }

    // 文件操作工具类（存在漏洞）
    public class FileOperationUtil {
        public void saveSimulationResult(String bizPath, String filename, String content) throws IOException {
            // 漏洞点：直接拼接路径
            String fullPath = uploadPath + File.separator + bizPath + File.separator + filename;
            
            // 创建目录结构
            File dir = new File(uploadPath + File.separator + bizPath);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            // 写入文件
            try (FileOutputStream fos = new FileOutputStream(fullPath)) {
                fos.write(content.getBytes());
            }
        }

        public String readSimulationResult(String bizPath, String filename) throws IOException {
            // 漏洞复现点
            String fullPath = uploadPath + File.separator + bizPath + File.separator + filename;
            StringBuilder content = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new FileReader(fullPath))) {
                String line;
                while ((line = br.readLine()) != null) {
                    content.append(line).append("\
");
                }
            }
            return content.toString();
        }
    }

    // 仿真任务处理器
    public class SimulationTask {
        private String taskId;
        private FileOperationUtil fileUtil;

        public SimulationTask(String taskId) {
            this.taskId = taskId;
            this.fileUtil = new FileOperationUtil();
        }

        public void runSimulation() throws IOException {
            DataGenerator generator = new DataGenerator();
            String result = generator.generateSimulationData(100);
            
            // 存在漏洞的文件保存
            fileUtil.saveSimulationResult(taskId, "results.csv", result);
            
            // 读取验证
            String verification = fileUtil.readSimulationResult(taskId, "results.csv");
            System.out.println("Simulation completed. First line: " + verification.split("\\\
")[0]);
        }
    }

    public static void main(String[] args) {
        // 基础路径应为受限目录
        SimulationConfigManager manager = new SimulationConfigManager("/var/simulation_data");
        
        // 模拟用户输入（攻击者可控制bizPath参数）
        String userInputPath = "../../../../../tmp/evil_data"; // 恶意路径
        
        try {
            SimulationTask task = manager.new SimulationTask(userInputPath);
            task.runSimulation();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}