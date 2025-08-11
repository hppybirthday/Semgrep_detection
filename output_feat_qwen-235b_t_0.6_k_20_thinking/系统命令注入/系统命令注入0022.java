import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class IoTDeviceController {
    public static void main(String[] args) {
        // 模拟Web控制器接收用户输入
        String userInput = "temperature_sensor.log"; // 实际场景中可能来自HTTP请求参数
        if (args.length > 0) {
            userInput = args[0];
        }
        
        // 构造存在漏洞的系统命令
        List<String> commands = new ArrayList<>();
        commands.add("/bin/sh");
        commands.add("-c");
        commands.add("cat /sys/class/thermal/thermal_zone0/temp > " + userInput);
        
        // 函数式风格执行命令
        executeCommand(commands, output -> {
            System.out.println("采集结果：\
" + output);
        });
    }

    private static void executeCommand(List<String> commands, Consumer<String> resultHandler) {
        try {
            // 漏洞点：直接执行用户参与构造的命令
            ProcessBuilder pb = new ProcessBuilder(commands);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String output = reader.lines().collect(Collectors.joining("\
"));
            
            // 处理执行结果
            resultHandler.accept(output);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}