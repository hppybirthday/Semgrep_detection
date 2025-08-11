package com.example.vuln;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Base64;

/**
 * 不安全的反序列化漏洞示例，用于云原生微服务架构
 */
@RestController
@RequestMapping("/api")
public class VulnerableDeserializationController {

    /**
     * 漏洞端点：接收Base64编码的序列化对象并反序列化
     * 攻击者可通过构造恶意序列化数据触发RCE
     */
    @GetMapping("/vulnerable")
    public String vulnerableEndpoint(@RequestParam String payload) {
        try {
            // 解码Base64数据
            byte[] data = Base64.getDecoder().decode(payload);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            // 不安全的反序列化操作
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object obj = ois.readObject();
            ois.close();

            // 元编程示例：动态代理处理反序列化对象
            InvocationHandler handler = new DynamicInvocationHandler(obj);
            Object proxy = Proxy.newProxyInstance(
                obj.getClass().getClassLoader(),
                obj.getClass().getInterfaces(),
                handler
            );

            // 调用代理对象的方法，可能触发漏洞
            Method method = proxy.getClass().getMethod("toString");
            method.invoke(proxy);

            return "Deserialized and proxied object: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Error during deserialization: " + e.getMessage();
        }
    }

    /**
     * 动态代理处理器，用于演示元编程技术
     */
    public static class DynamicInvocationHandler implements InvocationHandler {
        private Object target;

        public DynamicInvocationHandler(Object target) {
            this.target = target;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // 在方法调用前后执行额外逻辑
            System.out.println("Before method: " + method.getName());
            Object result = method.invoke(target, args);
            System.out.println("After method: " + method.getName());
            return result;
        }
    }

    /**
     * 示例可序列化服务接口，可能被攻击者利用动态代理
     */
    public interface VulnerableService extends Serializable {
        String executeTask(String param);
    }

    /**
     * 示例可序列化实现类，正常情况下执行任务
     */
    public static class TaskService implements VulnerableService {
        @Override
        public String executeTask(String param) {
            return "Task executed with param: " + param;
        }
    }

    /**
     * 辅助方法，用于生成恶意序列化数据（仅作演示，实际攻击由外部进行）
     */
    public static String generateMaliciousPayload() throws Exception {
        // 正常情况下不会在这里生成恶意数据，此处仅演示如何构造
        // 实际攻击会通过外部构造恶意序列化流
        VulnerableService task = new TaskService();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(task);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    /**
     * 测试端点，用于本地验证代码可编译性
     */
    @GetMapping("/test")
    public String testEndpoint() {
        return "Test endpoint is working.";
    }
}