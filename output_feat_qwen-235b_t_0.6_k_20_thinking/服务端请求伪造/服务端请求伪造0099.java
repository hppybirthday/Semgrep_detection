import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

interface TaskExecutor {
    String executeTask(String requestUrl);
}

abstract class AbstractTaskExecutor implements TaskExecutor {
    protected abstract String sendPost(String url, String content);
    protected abstract void logDetailCat(String content);
}

class WebHookTaskExecutor extends AbstractTaskExecutor {
    @Override
    protected String sendPost(String url, String content) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(url);
            // 漏洞点：直接使用用户输入构造请求
            CloseableHttpResponse response = httpClient.execute(httpPost);
            HttpEntity entity = response.getEntity();
            return entity != null ? EntityUtils.toString(entity) : "";
        } catch (IOException e) {
            logKill("Error: " + e.getMessage());
            return "Error";
        }
    }

    @Override
    protected void logDetailCat(String content) {
        System.out.println("[LOG] " + content.replaceAll("[<>]", "")); // HTML转义不完全
    }

    private void logKill(String message) {
        System.err.println("[ERROR] " + message);
    }
}

class TaskService {
    private final TaskExecutor executor;

    public TaskService(TaskExecutor executor) {
        this.executor = executor;
    }

    public String processTask(String requestUrl) {
        String response = executor.executeTask(requestUrl);
        executor.logDetailCat("Task response: " + response);
        return response;
    }
}

public class Main {
    public static void main(String[] args) {
        TaskExecutor executor = new WebHookTaskExecutor();
        TaskService service = new TaskService(executor);
        
        // 模拟用户输入
        String userInput = "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance";
        service.processTask(userInput);
    }
}