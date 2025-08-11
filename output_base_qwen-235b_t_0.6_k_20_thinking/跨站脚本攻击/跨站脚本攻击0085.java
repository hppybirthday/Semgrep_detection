import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class XXEMetaServer {
    public static void main(String[] args) throws Exception {
        Server server = new Server(8080);
        server.setHandler(new MetaHandler());
        server.start();
        server.join();
    }
}

class MetaHandler extends AbstractHandler {
    private final Map<String, Object> serviceRegistry = new HashMap<>();

    public MetaHandler() {
        serviceRegistry.put("UserService", new UserService());
    }

    @Override
    public void handle(String target, org.eclipse.jetty.server.Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String[] pathParts = target.split("/", 4);
            if (pathParts.length < 3) return;

            String serviceName = pathParts[1] + "Service";
            String methodName = pathParts[2];
            
            Object service = serviceRegistry.get(serviceName);
            if (service == null) return;

            Method[] methods = service.getClass().getDeclaredMethods();
            for (Method method : methods) {
                if (method.getName().equals(methodName) && method.getParameterCount() == 1) {
                    String param = request.getParameter("q");
                    
                    // 元编程：动态方法调用
                    Object result = method.invoke(service, param);
                    
                    response.setContentType("text/html;charset=utf-8");
                    response.getWriter().write((String) result);
                    baseRequest.setHandled(true);
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class UserService {
    // 存在漏洞的动态响应生成
    public String getProfile(String username) {
        return "<div class='profile'>" +
               "<h1>Welcome back, " + username + "!</h1>" +
               "<div class='settings'>Default settings loaded.</div>" +
               "</div>";
    }

    // 元编程扩展功能
    public String searchUser(String query) {
        return "Search results for: <b>" + query + "</b><br>No results found.";
    }
}