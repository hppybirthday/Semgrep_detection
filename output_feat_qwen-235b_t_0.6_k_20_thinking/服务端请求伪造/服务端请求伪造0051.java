package com.example.taskmanager;

import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import java.io.IOException;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    
    @PostMapping("/import")
    public String importTasks(@RequestBody String taskData) {
        JSONObject data = new JSONObject(taskData);
        String src = data.getString("src");
        String srcB = data.getString("srcB");
        
        TaskService taskService = new TaskService();
        String result = taskService.processTasks(src, srcB);
        
        return "Tasks imported: " + result;
    }
}

class TaskService {
    public String processTasks(String src, String srcB) {
        String taskData = RequestUtil.fetchData(src);
        String taskDataB = RequestUtil.fetchData(srcB);
        // Process and merge tasks
        return taskData + " | " + taskDataB;
    }
}

class RequestUtil {
    public static String fetchData(String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            return EntityUtils.toString(httpClient.execute(request).getEntity());
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
    }
}