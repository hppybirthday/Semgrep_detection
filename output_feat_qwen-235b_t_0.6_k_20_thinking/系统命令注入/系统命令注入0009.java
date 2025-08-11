import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

@ServerEndpoint("/data-processing")
public class DataProcessingWebSocket {
    private static final ObjectMapper mapper = new ObjectMapper();

    @OnMessage
    public void onMessage(String message, Session session) {
        try {
            Map<String, Object> payload = mapper.readValue(message, Map.class);
            String taskType = (String) payload.get("taskType");
            Map<String, String> params = (Map<String, String>) payload.get("params");
            
            if("HADOOP_JOB".equals(taskType)) {
                HadoopJobTask task = new HadoopJobTask();
                task.execute(params);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class HadoopJobTask {
        void execute(Map<String, String> params) throws IOException {
            String inputPath = params.get("inputPath");
            String outputPath = params.get("outputPath");
            String scriptPath = "/opt/hadoop-scripts/process.sh";
            
            // 漏洞点：直接拼接用户输入到命令中
            String command = String.format("%s -i %s -o %s", 
                scriptPath, inputPath, outputPath);
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            Process process = pb.start();
            
            // 模拟执行结果处理
            int exitCode = process.waitFor();
            System.out.println("Job exited with code: " + exitCode);
        }
    }

    public static void main(String[] args) {
        // WebSocket server启动逻辑（简化）
        System.out.println("WebSocket server started");
    }
}