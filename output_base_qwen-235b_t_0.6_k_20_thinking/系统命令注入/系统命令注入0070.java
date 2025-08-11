import java.io.*;
import java.util.Scanner;

public class IoTDeviceController {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("IoT设备管理系统 v1.0");
        System.out.print("请输入传感器ID进行数据采集：");
        String sensorId = scanner.nextLine();
        
        if (sensorId.isEmpty()) {
            System.out.println("错误：传感器ID不能为空");
            return;
        }
        
        String command = "python /opt/sensor_scripts/read_data.py "+ sensorId;
        System.out.println("[调试信息] 执行命令：" + command);
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            String line;
            System.out.println("\
数据采集结果：");
            
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                System.err.println("错误信息：" + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("\
执行结束，退出码：" + exitCode);
            
        } catch (Exception e) {
            System.err.println("执行命令时发生错误：");
            e.printStackTrace();
        }
        
        System.out.println("数据采集流程完成");
    }
}