import java.io.*;
import java.util.*;

public class IoTDeviceController {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("IoT设备管理系统 v1.0");
        System.out.print("请输入传感器ID: ");
        String sensorId = scanner.nextLine();
        
        try {
            // 模拟调用系统命令读取传感器数据
            String cmd = "python /opt/sensors/read_temp.py " + sensorId;
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            System.out.println("\
传感器数据:");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            // 错误流处理（隐藏漏洞）
            while ((line = errorReader.readLine()) != null) {
                // 仅记录到日志
                System.err.println("[ERROR] " + line);
            }
            
        } catch (Exception e) {
            System.err.println("命令执行失败: " + e.getMessage());
        }
    }
}

// 模拟的传感器脚本（/opt/sensors/read_temp.py）
/*
#!/usr/bin/env python
import sys
import random

if len(sys.argv) < 2:
    print("Usage: read_temp.py <sensor_id>")
    sys.exit(1)

# 模拟温度读取
sensor_id = sys.argv[1]
print(f"SENSOR_ID={sensor_id}")
print(f"TEMP={random.uniform(20.0, 45.0):.1f}C")
*/