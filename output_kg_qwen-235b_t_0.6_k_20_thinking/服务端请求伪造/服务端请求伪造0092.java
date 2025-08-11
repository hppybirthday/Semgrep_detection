package com.example.mathsim;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

/**
 * 数学建模仿真服务类
 * 模拟从外部数据源获取数据进行模型训练
 */
public class MathModelService {
    // 模拟训练参数
    private String datasetUrl;
    private int iterationCount;
    
    public MathModelService(String datasetUrl, int iterationCount) {
        this.datasetUrl = datasetUrl;
        this.iterationCount = iterationCount;
    }
    
    /**
     * 执行模型训练流程
     * @throws IOException 网络或数据异常
     */
    public void trainModel() throws IOException {
        String rawData = downloadDataFromExternalSource(datasetUrl);
        double[] processedData = processData(rawData);
        executeTraining(processedData);
    }
    
    /**
     * 从外部URL下载数据集
     * 存在SSRF漏洞：直接使用用户提供的URL进行请求
     */
    private String downloadDataFromExternalSource(String url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }
    
    /**
     * 简单数据预处理
     */
    private double[] processData(String rawData) {
        // 模拟数据处理逻辑
        String[] lines = rawData.split("\
");
        double[] result = new double[lines.length];
        for (int i = 0; i < lines.length; i++) {
            result[i] = Double.parseDouble(lines[i].trim());
        }
        return result;
    }
    
    /**
     * 执行模型训练
     */
    private void executeTraining(double[] data) {
        // 模拟迭代训练过程
        for (int i = 0; i < iterationCount; i++) {
            double error = calculateError(data, i);
            System.out.println("Iteration " + (i+1) + ", Error: " + error);
            if (error < 0.001) break;
        }
    }
    
    /**
     * 计算当前迭代误差
     */
    private double calculateError(double[] data, int iteration) {
        // 模拟误差计算
        double sum = 0;
        for (double d : data) {
            sum += d * Math.random() * iteration;
        }
        return Math.abs(sum / data.length);
    }
    
    public static void main(String[] args) {
        try {
            // 模拟用户输入
            String userInputUrl = "http://example.com/dataset.txt"; // 恶意用户可能修改此值
            int iteration = 100;
            
            MathModelService service = new MathModelService(userInputUrl, iteration);
            service.trainModel();
        } catch (IOException e) {
            System.err.println("数据下载失败: " + e.getMessage());
        }
    }
}