import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class BankApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankApplication.class, args);
    }
}

@RestController
class SSRFController {
    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, Object> serviceProxy = new HashMap<>();

    public SSRFController() {
        // 元编程动态注册内部服务代理
        serviceProxy.put("accountService", new AccountService());
    }

    @GetMapping("/api/external")
    public String handleExternalRequest(
            @RequestParam String service,
            @RequestParam String method,
            @RequestParam String targetUrl) {
        try {
            // 危险的反射调用链
            Object serviceInstance = serviceProxy.get(service);
            Method m = serviceInstance.getClass().getMethod(method, String.class);
            
            // 漏洞关键点：拼接用户输入的URL并发起请求
            String dynamicUrl = "https://external-api.bank.com/data?source=" + targetUrl;
            String response = restTemplate.getForObject(dynamicUrl, String.class);
            
            // 二次反射调用处理响应
            return (String) m.invoke(serviceInstance, response);
        } catch (Exception e) {
            return "Error processing request";
        }
    }
}

class AccountService {
    public String processAccountData(String rawData) {
        // 模拟敏感数据处理
        return "Account summary: $1,000,000";
    }
}