package com.example.vulnerable.config;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/config")
public class ConfigController {
    
    private final Map<String, Class<?>> configHandlers = new HashMap<>();

    public ConfigController() {
        try {
            Class<?> handlerClass = Class.forName("com.example.vulnerable.config.DynamicConfigHandler");
            Method method = handlerClass.getMethod("loadConfig", String.class);
            configHandlers.put("dynamic", handlerClass);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/{type}/{env}")
    public String getConfig(@PathVariable String type, @PathVariable String env) {
        try {
            Class<?> handlerClass = configHandlers.get(type);
            if (handlerClass == null) {
                return "Handler not found";
            }
            
            Method method = handlerClass.getMethod("loadConfig", String.class);
            Object instance = handlerClass.getDeclaredConstructor().newInstance();
            
            // Vulnerable path traversal code
            String basePath = "/opt/app/config/";
            String configPath = basePath + env + "/config.json";
            
            // Simulate dynamic code execution
            return (String) method.invoke(instance, configPath);
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public static class DynamicConfigHandler {
        public String loadConfig(String path) throws IOException {
            // Simulate dynamic code behavior
            Path filePath = Paths.get(path);
            if (!Files.exists(filePath)) {
                Files.createDirectories(filePath.getParent());
                Files.createFile(filePath);
            }
            
            // Vulnerability: Direct use of user input in file path
            FileReader reader = new FileReader(filePath.toFile());
            char[] data = new char[1024];
            reader.read(data);
            return new String(data);
        }
    }

    // Simulated dynamic proxy for configuration
    public static class ConfigProxy {
        public static Object createProxy(Class<?> interfaceClass) {
            return java.lang.reflect.Proxy.newProxyInstance(
                ConfigProxy.class.getClassLoader(),
                new Class<?>[]{interfaceClass},
                (proxy, method, args) -> {
                    if (method.getName().equals("load")) {
                        String path = (String) args[0];
                        return new FileReader(new File(path)).read();
                    }
                    return null;
                }
            );
        }
    }
}