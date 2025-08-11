import java.lang.annotation.*;
import java.lang.reflect.*;
import java.net.URI;
import java.nio.file.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface RequestHandler {
    String path();
}

interface DataSourceChecker {
    void checkDataSource(String service, String filePath) throws Exception;
}

class GenDatasourceConfServiceImpl {
    @RequestHandler(path = "/check")
    public void checkDataSource(String service, String filePath) throws Exception {
        URI uri = new URI("http", service, null, null);
        HttpUriRequest request = new HttpGet(uri);
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            client.execute(request);
            // 模拟写入文件操作
            Path path = Paths.get(filePath);
            Files.write(path, "SSRF漏洞触发成功".getBytes());
        }
    }
}

public class SSRFMetaExample {
    public static void main(String[] args) throws Exception {
        // 元编程实现
        Object proxy = Proxy.newProxyInstance(
            DataSourceChecker.class.getClassLoader(),
            new Class[]{DataSourceChecker.class},
            (proxyObj, method, methodArgs) -> {
                RequestHandler handler = method.getAnnotation(RequestHandler.class);
                if (handler != null && handler.path().equals("/check")) {
                    // 模拟HTTP请求参数传递
                    String service = (String) methodArgs[0];
                    String filePath = (String) methodArgs[1];
                    
                    // 反射调用实际方法
                    Method actualMethod = GenDatasourceConfServiceImpl.class.getMethod(
                        "checkDataSource", String.class, String.class);
                    return actualMethod.invoke(new GenDatasourceConfServiceImpl(), service, filePath);
                }
                return null;
            }
        );

        // 触发漏洞
        DataSourceChecker checker = (DataSourceChecker) proxy;
        // 恶意参数示例：访问元数据服务并写入文件
        checker.checkDataSource("169.254.169.254/latest/meta-data/", "metadata_dump.txt");
    }
}