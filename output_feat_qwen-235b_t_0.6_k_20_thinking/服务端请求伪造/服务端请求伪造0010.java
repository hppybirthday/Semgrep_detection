import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DataCleanerServlet extends HttpServlet {
    private static final Pattern IMAGE_PATTERN = Pattern.compile(".*\\.(jpg|png|gif)$");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String imageUri = request.getParameter("imageUri");
        String notifyUrl = request.getParameter("notifyUrl");
        
        if (imageUri == null || notifyUrl == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameters");
            return;
        }

        try {
            // 模拟数据清洗流程
            if (!validateImageUri(imageUri)) {
                sendError(notifyUrl, "Invalid image format");
                return;
            }

            String cleanedData = processImage(imageUri);
            sendSuccess(notifyUrl, cleanedData);
            
        } catch (Exception e) {
            sendError(notifyUrl, "Processing failed: " + e.getMessage());
        }
    }

    private boolean validateImageUri(String uri) {
        return IMAGE_PATTERN.matcher(uri).matches();
    }

    private String processImage(String uri) throws IOException {
        // 漏洞点：直接使用用户输入的URI发起请求
        HttpGet request = new HttpGet(URI.create(uri));
        
        try (CloseableHttpClient client = HttpClients.createDefault();
             HttpResponse response = client.execute(request)) {
                
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent()));
            
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
            
            // 模拟数据清洗操作
            return cleanImageData(result.toString());
            
        } catch (IOException e) {
            throw new IOException("Image processing error: " + e.getMessage());
        }
    }

    private String cleanImageData(String rawData) {
        // 简单的模拟清洗操作
        return rawData.replaceAll("<script>.*?</script>", "");
    }

    private void sendSuccess(String notifyUrl, String data) throws IOException {
        // 构造包含处理结果的JSON请求
        HttpPost post = new HttpPost(URI.create(notifyUrl));
        String json = String.format("{\\"status\\":\\"success\\",\\"data\\":%s}", data);
        post.setEntity(new StringEntity(json));
        
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            client.execute(post);
        } catch (IOException e) {
            // 忽略通知失败
        }
    }

    private void sendError(String notifyUrl, String message) throws IOException {
        // 漏洞点：未验证notifyUrl的有效性
        HttpPost post = new HttpPost(URI.create(notifyUrl));
        String json = String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", message);
        post.setEntity(new StringEntity(json));
        
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            client.execute(post);
        } catch (IOException e) {
            // 忽略通知失败
        }
    }
}