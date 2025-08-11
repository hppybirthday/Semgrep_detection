import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.util.List;

public class ChatServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        BufferedReader reader = request.getReader();
        StringBuilder input = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            input.append(line);
        }
        
        // 模拟从请求中提取配置参数
        JSONObject rawJson = JSON.parseObject(input.toString());
        String dbKey = rawJson.getString("dbKey");
        String chatData = rawJson.getString("message");
        
        // 模拟Redis缓存操作（漏洞触发点）
        CacheManager cache = new CacheManager();
        ChatMessage message = (ChatMessage) cache.getCache(dbKey, chatData);
        
        // 模拟消息处理逻辑
        if(message != null) {
            System.out.println("Received message from: " + message.getUser());
            response.getWriter().write("Message received");
        }
    }
}

class ChatMessage implements Serializable {
    private String user;
    private String content;
    
    // Getters and setters
    public String getUser() { return user; }
    public void setUser(String user) { this.user = user; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

class CacheManager {
    public Object getCache(String key, String value) {
        // 模拟从Redis获取缓存数据
        if(key.contains("malicious")) {
            // 模拟恶意数据注入（真实场景中攻击者通过其他途径注入）
            value = "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\",\\"_bytecodes\\":[\\"rO0ABXNyABxjb20uc3VuLm9yZy5hcGFjaGUueG1scy5pbnRlcm5hbC54c2x0Yy5ydW50aW1lLlRlbXBsYXRlcyR2l0YWxTdGlja3kBAEA=\\"],\\"_name\\":\\"a1\\",\\"_tfactory\\":{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl\\"}}";
        }
        
        // 危险的反序列化操作（漏洞核心）
        return JSON.parseObject(value, ChatMessage.class);
    }
}