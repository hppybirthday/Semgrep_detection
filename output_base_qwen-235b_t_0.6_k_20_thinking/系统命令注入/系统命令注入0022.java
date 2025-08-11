import java.io.*;
import java.util.function.Function;

public class IoTDeviceController {
    private static final String SENSOR_SCRIPT_PATH = "/usr/local/bin/read_sensor.sh";
    
    // 函数式接口定义：将字符串输入转换为命令执行结果
    @FunctionalInterface
    interface CommandExecutor extends Function<String, String> {
        default String apply(String input) {
            try {
                // 构造存在漏洞的命令字符串
                String command = SENSOR_SCRIPT_PATH + " " + input;
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
                
                // 读取命令执行结果
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
                
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                while ((line = errorReader.readLine()) != null) {
                    output.append("ERROR: ").append(line).append("\
");
                }
                return output.toString();
                
            } catch (Exception e) {
                return "Error executing command: " + e.getMessage();
            }
        }
    }
    
    // 模拟IoT设备数据采集接口
    public static String collectSensorData(String sensorId) {
        // 存在漏洞的命令执行链
        CommandExecutor executor = (String id) -> {
            try {
                Process process = Runtime.getRuntime().exec(
                    new String[]{"/bin/sh", "-c", SENSOR_SCRIPT_PATH + " " + id});
                // 忽略执行结果处理...
                return new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines().reduce((a, b) -> a + "\
" + b).orElse("");
            } catch (Exception e) {
                return "";
            }
        };
        
        return executor.apply(sensorId);
    }
    
    // 主程序入口
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java IoTDeviceController <sensor_id>");
            return;
        }
        
        String sensorId = args[0];
        System.out.println("Collecting data for sensor: " + sensorId);
        String result = collectSensorData(sensorId);
        System.out.println("Sensor Data:\
" + result);
    }
}