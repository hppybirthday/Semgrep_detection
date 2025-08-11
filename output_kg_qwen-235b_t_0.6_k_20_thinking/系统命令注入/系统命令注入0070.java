package com.iot.example;

import java.io.*;
import java.util.Scanner;
import java.util.logging.Logger;

public class IoTDeviceController {
    private static final Logger logger = Logger.getLogger(IoTDeviceController.class.getName());

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("IoT设备数据采集系统");
        System.out.print("请输入设备ID: ");
        String deviceId = scanner.nextLine();

        try {
            String sensorData = collectSensorData(deviceId);
            System.out.println("采集到的数据: " + sensorData);
        } catch (Exception e) {
            System.err.println("数据采集失败: " + e.getMessage());
        }
    }

    private static String collectSensorData(String deviceId) throws IOException, InterruptedException {
        // 模拟调用本地脚本采集传感器数据
        String command = "./read_sensor.sh " + deviceId;
        
        // 记录执行命令（调试用）
        logger.info("执行命令: " + command);
        
        // 存在漏洞的命令执行方式
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取命令输出
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream(), outputStream);
        StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream(), outputStream);
        
        Thread outputThread = new Thread(outputGobbler);
        Thread errorThread = new Thread(errorGobbler);
        outputThread.start();
        errorThread.start();
        
        int exitCode = process.waitFor();
        outputThread.join();
        errorThread.join();
        
        if (exitCode != 0) {
            throw new RuntimeException("命令执行失败，退出码: " + exitCode);
        }
        
        return outputStream.toString();
    }
    
    // 辅助类用于读取流输出
    static class StreamGobbler implements Runnable {
        private final InputStream inputStream;
        private final ByteArrayOutputStream outputStream;
        
        public StreamGobbler(InputStream inputStream, ByteArrayOutputStream outputStream) {
            this.inputStream = inputStream;
            this.outputStream = outputStream;
        }
        
        @Override
        public void run() {
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    outputStream.write(line.getBytes());
                    outputStream.write(System.lineSeparator().getBytes());
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}