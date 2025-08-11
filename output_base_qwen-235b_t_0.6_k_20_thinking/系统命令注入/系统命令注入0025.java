import java.io.*;
import java.lang.reflect.*;
import java.util.*;

public class BigDataProcessor {
    public static void main(String[] args) {
        try {
            Class<?> cmdClass = Class.forName("com.example.hadoop.HadoopJob");
            Object jobInstance = cmdClass.getDeclaredConstructor().newInstance();
            
            Method setParam = cmdClass.getMethod("setJobParam", String.class, String.class);
            Scanner scanner = new Scanner(System.in);
            
            System.out.print("Enter processing date (YYYY-MM-DD): ");
            String userInput = scanner.nextLine();
            
            // 动态构造Hadoop流命令参数（存在漏洞）
            String[] commands = {
                "hadoop",
                "jar",
                "/opt/hadoop-streaming.jar",
                "-D", "mapreduce.job.reduces=1",
                "-files", "/data/scripts/mapper.py,/data/scripts/reducer.py",
                "-mapper", "mapper.py",
                "-reducer", "reducer.py",
                "-input", "/data/input/" + userInput,
                "-output", "/data/output/" + userInput
            };
            
            ProcessBuilder pb = new ProcessBuilder(commands);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("\
Exit code: " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模拟的Hadoop作业配置类
class HadoopJob {
    private Map<String, String> params = new HashMap<>();
    
    public void setJobParam(String key, String value) {
        params.put(key, value);
    }
    
    public ProcessBuilder buildJob() {
        return new ProcessBuilder("bash", "-c", "echo 'Processing data' && exit 0");
    }
}