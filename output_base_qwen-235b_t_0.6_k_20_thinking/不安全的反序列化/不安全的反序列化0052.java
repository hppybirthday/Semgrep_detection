import java.io.*;
import java.util.*;
import java.util.function.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.*;
import org.springframework.web.reactive.function.server.*;

@SpringBootApplication
public class VulnerableWebApp {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableWebApp.class, args);
    }

    public static RouterFunction<ServerResponse> vulnerableRoute() {
        return RouterFunctions.route(RequestPredicates.POST("/deserialize"),
            request -> request.bodyToMono(String.class)
                .map(VulnerableWebApp::unsafeDeserialize)
                .flatMap(user -> ServerResponse.ok().bodyValue("Welcome " + user.getName())));
    }

    @SuppressWarnings("unchecked")
    private static <T> T unsafeDeserialize(String data) {
        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded))) {
                return (T) ois.readObject(); // 不安全的反序列化
            }
        } catch (Exception e) {
            throw new RuntimeException("Deserialization failed", e);
        }
    }
}

// 模拟用户类
class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;

    public User(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    // 模拟业务逻辑中的潜在攻击面
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if ("admin".equals(name)) {
            Runtime.getRuntime().exec("/bin/sh -c echo 'Unauthorized access'"); // 恶意代码示例
        }
    }
}