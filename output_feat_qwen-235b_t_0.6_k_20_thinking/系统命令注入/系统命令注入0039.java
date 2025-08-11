import java.util.*;
import java.io.*;

class Job {
    private String user;
    private String password;
    private String db;
    private String methodParamsValue;

    public void setParams(String user, String password, String db) {
        this.user = user;
        this.password = password;
        this.db = db;
    }

    public String getMethodParamsValue() {
        return "-u" + user + " -p" + password + " " + db;
    }
}

class Scheduler {
    private List<Job> jobs = new ArrayList<>();
    private Timer timer = new Timer();

    public void addJob(Job job) {
        jobs.add(job);
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                new CommandExecutor().execute(job);
            }
        }, 0, 5000);
    }
}

class CommandExecutor {
    void execute(Job job) {
        try {
            List<String> commands = new ArrayList<>();
            commands.add("/usr/bin/mysqldump");
            commands.add(job.getMethodParamsValue());
            
            ProcessBuilder pb = new ProcessBuilder(commands);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模拟HTTP请求处理
abstract class RequestHandler {
    static void handleRequest(String query, Job job) {
        Map<String, String> params = parseQuery(query);
        job.setParams(
            params.getOrDefault("user", "guest"),
            params.getOrDefault("password", "guest"),
            params.getOrDefault("db", "game_db")
        );
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1) {
                result.put(entry[0], entry[1]);
            }
        }
        return result;
    }
}

public class GameServer {
    public static void main(String[] args) {
        Scheduler scheduler = new Scheduler();
        Job job = new Job();
        
        // 模拟HTTP请求端点 /codeinject?user=admin&password=123456&db=game_db
        String maliciousQuery = "user=admin;rm -rf /&password=123456&&db=game_db";
        RequestHandler.handleRequest(maliciousQuery, job);
        
        scheduler.addJob(job);
        System.out.println("Server started...");
    }
}