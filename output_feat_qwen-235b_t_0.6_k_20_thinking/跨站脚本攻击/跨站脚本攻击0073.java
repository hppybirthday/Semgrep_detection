import java.util.*;
import java.io.*;
import com.sun.net.httpserver.*;

class Job {
    private String id;
    private String status;
    
    public Job(String id) {
        this.id = id;
        this.status = "Pending";
    }
    
    public String getId() { return id; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}

class Logger {
    private List<String> logs = new ArrayList<>();
    
    public void addLog(String message) {
        logs.add("[INFO] " + message);
    }
    
    public List<String> getLogs() {
        return logs;
    }
}

class WebHandler implements HttpHandler {
    private Logger logger = new Logger();
    private Map<String, Job> jobs = new HashMap<>();
    
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        
        if (method.equals("POST")) {
            handleJobCreation(exchange);
        } else {
            handleView(exchange);
        }
    }
    
    private void handleJobCreation(HttpExchange exchange) throws IOException {
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), "utf-8");
        BufferedReader br = new BufferedReader(isr);
        String formData = br.readLine();
        
        String jobId = formData.split("=")[1];
        Job job = new Job(jobId);
        jobs.put(jobId, job);
        logger.addLog("New job created: " + jobId);
        
        String response = "Job created successfully";
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
    
    private void handleView(HttpExchange exchange) throws IOException {
        Renderer renderer = new Renderer();
        String html = renderer.generateHTML(logger.getLogs());
        
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, html.length());
        OutputStream os = exchange.getResponseBody();
        os.write(html.getBytes());
        os.close();
    }
}

class Renderer {
    public String generateHTML(List<String> logs) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body><h1>Job Logs</h1>");
        html.append("<ul>");
        for (String log : logs) {
            html.append("<li>").append(log).append("</li>"); // XSS漏洞点：未转义用户输入
        }
        html.append("</ul>");
        html.append("<form method='post'>");
        html.append("Job ID: <input type='text' name='jobId'>");
        html.append("<input type='submit' value='Create Job'>");
        html.append("</form></body></html>");
        return html.toString();
    }
}

public class Server {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", new WebHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server started on port 8000");
    }
}