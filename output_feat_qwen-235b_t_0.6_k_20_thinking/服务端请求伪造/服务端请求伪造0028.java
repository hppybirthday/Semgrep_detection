import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@Service
class LogService {
    private final String baseApi = "http://internal-monitoring-api/";

    public String fetchLogDetails(String imageUrl) throws Exception {
        URL url = new URL(baseApi + "logDetailCat?img=" + imageUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        conn.disconnect();
        return content.toString();
    }

    public void killLogProcess(String target) throws Exception {
        URL url = new URL("http://localhost:8080/joblog/kill?process=" + target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.getInputStream().close();
        conn.disconnect();
    }
}

@RestController
@RequestMapping("/joblog")
class LogController {
    private final LogService logService = new LogService();

    @GetMapping("/logDetailCat")
    public String getLogDetails(@RequestParam String imageUrl) throws Exception {
        return logService.fetchLogDetails(imageUrl);
    }

    @PostMapping("/logKill")
    public void terminateLog(@RequestParam String target) throws Exception {
        logService.killLogProcess(target);
    }

    // 模拟CRM核心业务逻辑
    @PostMapping("/create")
    public String createTaskLog(@RequestParam String imageUrl) {
        try {
            String result = logService.fetchLogDetails(imageUrl);
            // 存储缩略图URL到数据库
            return "{\\"thumbnail\\":\\"" + result.split(",")[0] + "\\"}";
        } catch (Exception e) {
            return "{\\"error\\":\\"Invalid image URL\\"}";
        }
    }
}

// 模拟Spring Boot启动类
@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}