import java.io.File;
import java.lang.reflect.Method;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

public class GameModLoader {
    public static void main(String[] args) {
        try {
            loadModConfig("user_config.json");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void loadModConfig(String configPath) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode config = mapper.readTree(new File(configPath));
        ArrayNode servers = (ArrayNode) config.get("servers");
        
        Class<?> httpClass = Class.forName("org.apache.http.impl.client.HttpClients");
        Method createMethod = httpClass.getMethod("createDefault");
        CloseableHttpClient httpClient = (CloseableHttpClient) createMethod.invoke(null);
        
        for (int i = 0; i < servers.size(); i++) {
            if (i == 2) {
                String target = servers.get(i).asText();
                HttpGet request = new HttpGet(target);
                CloseableHttpResponse response = httpClient.execute(request);
                
                try {
                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        String result = EntityUtils.toString(entity);
                        System.out.println("Server response: " + result.substring(0, Math.min(200, result.length())));
                    }
                } finally {
                    response.close();
                }
            }
        }
    }
}