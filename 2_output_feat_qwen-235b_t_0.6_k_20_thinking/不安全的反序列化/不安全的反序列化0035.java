package com.crm.auth.config;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * 认证配置管理控制器
 * 提供第三方认证参数动态配置功能
 */
@RestController
@RequestMapping("/api/v1/config")
public class AuthProviderController {
    private final AuthService authService;

    public AuthProviderController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * 获取认证提供方配置
     * @param request HTTP请求
     * @return 认证配置信息
     */
    @GetMapping("/auth-provider")
    public Map<String, Object> getAuthProviderConfig(HttpServletRequest request) {
        String rememberMe = request.getParameter("rememberMe");
        if (rememberMe == null || rememberMe.isEmpty()) {
            return authService.getDefaultConfig();
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(rememberMe);
            // 解析用户自定义配置
            return authService.parseConfig(new String(decoded));
        } catch (IllegalArgumentException e) {
            return authService.getDefaultConfig();
        }
    }
}

class AuthService {
    private final JsonUtils jsonUtils;

    public AuthService(JsonUtils jsonUtils) {
        this.jsonUtils = jsonUtils;
    }

    Map<String, Object> getDefaultConfig() {
        return Map.of("authProviders", List.of("internal"));
    }

    Map<String, Object> parseConfig(String configData) {
        Map<String, Object> result = jsonUtils.jsonToObject(configData, Map.class);
        if (result.containsKey("authProviders")) {
            return result;
        }
        return getDefaultConfig();
    }
}

class JsonUtils {
    <T> T jsonToObject(String json, Class<T> clazz) {
        // 使用FastJSON进行反序列化
        return JSON.parseObject(json, clazz);
    }
}