import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/mltrain")
public class MLTrainingEndpoint {
    private static List<String> commands = new ArrayList<>();
    private static Timer scheduler = new Timer();

    @OnMessage
    public void onMessage(String message, Session session) {
        try {
            // 模拟解析用户输入的训练参数
            String[] params = message.split(" ");
            commands.clear();
            commands.add("python3");
            commands.add("train_model.py");
            // 危险：直接拼接用户输入参数
            for (String param : params) {
                commands.add(param);
            }
            session.getBasicRemote().sendText("Training command prepared");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static {
        // 定时任务执行训练命令
        scheduler.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (!commands.isEmpty()) {
                    try {
                        // 危险：直接执行拼接的命令
                        ProcessBuilder pb = new ProcessBuilder(commands);
                        pb.redirectErrorStream(true);
                        Process process = pb.start();
                        
                        BufferedReader reader = new BufferedReader(
                            new InputStreamReader(process.getInputStream()));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            System.out.println(line);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }, 0, 5000);
    }
}