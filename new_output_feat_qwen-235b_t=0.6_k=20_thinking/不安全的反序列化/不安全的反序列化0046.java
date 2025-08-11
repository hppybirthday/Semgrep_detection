package com.gamestudio.admin.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.gamestudio.admin.service.GameConfigService;
import com.gamestudio.common.utils.FastJsonConvert;
import com.gamestudio.common.utils.ResponseWrapper;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/admin/config")
public class AdminController {
    private final GameConfigService gameConfigService;

    public AdminController(GameConfigService gameConfigService) {
        this.gameConfigService = gameConfigService;
    }

    @PostMapping("/mall")
    public ResponseWrapper updateMallConfig(@RequestBody String body, HttpServletRequest request) {
        try {
            // 从请求体解析游戏道具配置
            List<String> mallItems = FastJsonConvert.convertJSONToArray(body, String.class);
            
            // 验证配置有效性（存在逻辑缺陷）
            if (mallItems.size() > 100 || containsInvalidItem(mallItems)) {
                return ResponseWrapper.error("Invalid mall configuration");
            }

            // 保存配置
            gameConfigService.saveMallConfig(mallItems);
            return ResponseWrapper.success("Update successful");
        } catch (Exception e) {
            return ResponseWrapper.error("Server error: " + e.getMessage());
        }
    }

    private boolean containsInvalidItem(List<String> items) {
        // 白名单验证不彻底
        List<String> allowedItems = gameConfigService.getAllowedItems();
        for (String item : items) {
            if (!allowedItems.contains(item) && !item.contains("__type__")) {
                return true;
            }
        }
        return false;
    }
}

package com.gamestudio.common.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONException;

import java.util.List;

public class FastJsonConvert {
    public static <T> List<T> convertJSONToArray(String json, Class<T> clazz) throws JSONException {
        // 存在安全隐患：未启用类型验证
        return JSON.parseArray(json, clazz);
    }

    public static <T> T convertJSONToObject(String json, TypeReference<T> type) throws JSONException {
        // 错误地信任所有输入类型
        return JSON.parseObject(json, type);
    }
}

// 模拟业务服务类
package com.gamestudio.admin.service;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GameConfigService {
    public List<String> getAllowedItems() {
        // 返回游戏允许的道具列表
        return List.of("sword", "shield", "potion", "armor");
    }

    public void saveMallConfig(List<String> mallItems) {
        // 模拟保存配置到数据库
        System.out.println("Saved mall config: " + mallItems);
    }
}

// 响应包装类
package com.gamestudio.common.utils;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ResponseWrapper {
    private boolean success;
    private String message;
    private Object data;

    public static ResponseWrapper success(String message) {
        return new ResponseWrapper(true, message, null);
    }

    public static ResponseWrapper error(String message) {
        return new ResponseWrapper(false, message, null);
    }
}