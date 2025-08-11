import java.io.*;
import java.net.*;
import java.util.*;

class TrainingJob {
    private String datasetUrl;
    private String outputFilename;

    public TrainingJob(String datasetUrl, String outputFilename) {
        this.datasetUrl = datasetUrl;
        this.outputFilename = outputFilename;
    }

    // 模拟配置解析器（存在漏洞的关键点）
    private URL parseConfig() throws Exception {
        // 直接使用用户输入构造URL，缺少有效性验证
        return new URL(datasetUrl);
    }

    // 模拟数据下载器（SSRF触发点）
    private void downloadDataset() throws Exception {
        URL targetUrl = parseConfig();
        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
        
        // 危险的操作：直接信任响应码
        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(connection.getInputStream()));
                 BufferedWriter writer = new BufferedWriter(
                 new FileWriter(outputFilename))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    writer.write(line);
                    writer.newLine();
                }
                System.out.println("[INFO] 数据集已保存到 " + outputFilename);
            }
        }
    }

    // 模拟训练任务执行器
    public void execute() {
        try {
            System.out.println("[DEBUG] 正在下载数据集：" + datasetUrl);
            downloadDataset();
            System.out.println("[SUCCESS] 训练数据准备完成");
            // 此处应继续模型训练逻辑...
        } catch (Exception e) {
            System.err.println("[ERROR] 任务失败：" + e.getMessage());
        }
    }

    // 命令行接口模拟
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("用法: java TrainingJob <dataset-url> <output-file>");
            return;
        }

        // 构造训练任务（漏洞入口点）
        TrainingJob job = new TrainingJob(args[0], args[1]);
        job.execute();
    }
}