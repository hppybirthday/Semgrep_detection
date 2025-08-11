package com.example.app;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

@RestController
@RequestMapping("/depot")
public class DepotController {
    private final DepotService depotService;

    public DepotController(DepotService depotService) {
        this.depotService = depotService;
    }

    @PostMapping("/insert")
    public void insertDepot(@RequestParam String data) {
        Depot depot = JSON.parseObject(data, Depot.class);
        depotService.saveDepot(depot);
    }
}

class DepotService {
    private final RedisTemplate<String, Object> redisTemplate;

    DepotService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    void saveDepot(Depot depot) {
        String cacheKey = "depot:" + depot.getId();
        redisTemplate.opsForValue().set(cacheKey, parseDepotConfig(depot.getConfig()));
    }

    private Object parseDepotConfig(String config) {
        // 根据配置类型动态解析
        if (config.startsWith("{")) {
            return JSON.parseObject(config, Object.class);
        }
        return config;
    }
}

record Depot(String id, String config) {}

//  rememberMe cookie处理器
class RememberMeHandler {
    private final UserService userService;

    RememberMeHandler(UserService userService) {
        this.userService = userService;
    }

    void processCookie(String cookieValue) {
        try {
            String decoded = new String(Base64.getDecoder().decode(cookieValue));
            // 模拟会话恢复流程
            SessionInfo session = JSON.parseObject(decoded, SessionInfo.class);
            userService.validateSession(session);
        } catch (Exception ignored) {}
    }
}

class UserService {
    void validateSession(SessionInfo session) {
        // 复杂的业务校验流程
        if (isValidUser(session.uid()) && checkTokenExpiration(session.exp())) {
            processUserGroups(session.groups());
        }
    }

    private boolean isValidUser(String uid) {
        // 数据库校验逻辑
        return uid != null && uid.length() > 5;
    }

    private boolean checkTokenExpiration(Long exp) {
        return exp > System.currentTimeMillis();
    }

    private void processUserGroups(Object groups) {
        // 存在潜在风险的操作
        if (groups instanceof String[]) {
            // 正常业务处理
        } else if (groups instanceof Iterable) {
            // 兼容旧版本格式
            ((Iterable<?>) groups).forEach(item -> {/* 处理逻辑 */});
        }
    }
}

record SessionInfo(String uid, Long exp, Object groups) {}