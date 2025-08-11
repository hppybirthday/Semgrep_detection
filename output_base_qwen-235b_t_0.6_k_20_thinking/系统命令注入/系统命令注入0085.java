import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.stream.Collectors;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class CommandInjectionDemo {

    public static void main(String[] args) {
        SpringApplication.run(CommandInjectionDemo.class, args);
    }

    @PostMapping("/process")
    public ResponseEntity<String> processFile(@RequestParam String filename) {
        try {
            // 使用元编程动态获取执行方法
            Class<?> clazz = Class.forName("java.lang.Runtime");
            Method execMethod = clazz.getMethod("exec", String.class);
            
            // 构造危险的命令拼接（漏洞点）
            String command = "cat " + filename + " | wc -l";
            Process process = (Process) execMethod.invoke(Runtime.getRuntime(), command);
            
            // 获取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String result = reader.lines().collect(Collectors.joining("\
"));
            
            return ResponseEntity.ok("Line count: " + result);
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing file: " + e.getMessage());
        }
    }

    // 模拟企业级服务中的动态代理使用
    @GetMapping("/meta")
    public ResponseEntity<String> metaOperation(@RequestParam String operation) {
        try {
            Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class[]{Runnable.class},
                (proxy1, method, args) -> {
                    if (method.getName().equals("run")) {
                        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", operation);
                        builder.redirectErrorStream(true);
                        Process process = builder.start();
                        return process.waitFor();
                    }
                    return null;
                });
            
            Method runMethod = proxy.getClass().getMethod("run");
            runMethod.invoke(proxy);
            return ResponseEntity.ok("Operation completed");
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Meta error: " + e.getMessage());
        }
    }
}