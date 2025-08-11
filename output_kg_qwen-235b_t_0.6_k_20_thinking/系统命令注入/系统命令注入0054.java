package com.iot.secure;

import java.io.*;
import java.util.*;
import java.util.logging.*;

/**
 * @Description: IoT设备传感器数据采集控制器
 * @Author: iot_dev
 * @Date: 2024/5/15
 */
public class SensorDataCollector {
    private static final Logger logger = Logger.getLogger(SensorDataCollector.class.getName());
    private static final List<String> VALID_SENSORS = Arrays.asList("temp01", "humid02", "vibration_3", "pressureX");

    /**
     * 处理传感器数据采集请求
     * @param sensorId 用户指定的传感器ID
     * @return 采集结果
     */
    public String collectSensorData(String sensorId) {
        if (sensorId == null || sensorId.trim().isEmpty()) {
            throw new IllegalArgumentException("传感器ID不能为空");
        }

        // 防御式编程：检查传感器ID是否在白名单中
        if (!VALID_SENSORS.contains(sensorId)) {
            throw new IllegalArgumentException("不允许访问的传感器: " + sensorId);
        }

        try {
            // 漏洞点：使用拼接方式构造系统命令
            String command = String.format("/opt/iot_scripts/read_sensor.sh %s", sensorId);
            Process process = Runtime.getRuntime().exec(command);
            
            // 处理命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            logger.info(String.format("传感器%s数据采集完成，退出码: %d", sensorId, exitCode));
            return output.toString();
            
        } catch (Exception e) {
            logger.severe("数据采集失败: " + e.getMessage());
            return "数据采集失败: " + e.getMessage();
        }
    }

    /**
     * 模拟真实设备的传感器读取脚本
     * @param args
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("使用方式: java SensorDataCollector <传感器ID>");
            return;
        }
        
        SensorDataCollector collector = new SensorDataCollector();
        String result = collector.collectSensorData(args[0]);
        System.out.println("采集结果:");
        System.out.println(result);
    }
}

/**
 * 修复建议：应使用参数化方式执行命令
 */
/*
protected String secureCollectSensorData(String sensorId) {
    try {
        ProcessBuilder pb = new ProcessBuilder("/opt/iot_scripts/read_sensor.sh", sensorId);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        // 后续处理逻辑...
    } catch (Exception e) {
        // 错误处理...
    }
}
*/