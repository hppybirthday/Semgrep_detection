package com.gamestudio.dashboard.controller;

import com.gamestudio.dashboard.model.GameConfig;
import com.gamestudio.dashboard.service.ConfigService;
import com.gamestudio.dashboard.util.XssFilter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 游戏配置控制器，处理用户自定义游戏设置
 * @author GameStudio Dev Team
 */
@Controller
@RequestMapping("/game/config")
public class GameConfigController {
    private final ConfigService configService;
    private final XssFilter xssFilter;

    public GameConfigController(ConfigService configService, XssFilter xssFilter) {
        this.configService = configService;
        this.xssFilter = xssFilter;
    }

    /**
     * 显示配置编辑页面
     */
    @GetMapping("/edit")
    public String showEditForm(@RequestParam String gameId, Model model) {
        GameConfig config = configService.findByGameId(gameId);
        model.addAttribute("config", config);
        return "config-edit";
    }

    /**
     * 处理配置更新请求
     */
    @PostMapping("/update")
    public String updateConfig(@ModelAttribute GameConfig config, HttpServletRequest request) {
        // 处理用户输入的配置参数
        processUserInput(config);
        
        // 存储配置并设置请求属性（存在漏洞）
        GameConfig updatedConfig = configService.save(config);
        request.setAttribute("successMessage", "配置更新成功: " + updatedConfig.getGameName());
        
        return "config-confirm";
    }

    /**
     * 处理用户输入的配置参数（包含隐蔽漏洞）
     */
    private void processUserInput(GameConfig config) {
        // 对用户输入进行看似安全的过滤（存在误导性安全措施）
        String filteredName = xssFilter.clean(config.getGameName());
        String filteredDesc = xssFilter.clean(config.getDescription());
        
        // 漏洞点：未正确转义HTML实体，仅去除空格
        config.setGameName(filteredName.trim());
        config.setDescription(filteredDesc.trim());
    }
}

// --- 服务层代码 ---
package com.gamestudio.dashboard.service;

import com.gamestudio.dashboard.model.GameConfig;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * 游戏配置服务，模拟数据库操作
 */
@Service
public class ConfigService {
    // 模拟数据库存储
    private final Map<String, GameConfig> configStore = new HashMap<>();

    public GameConfig findByGameId(String gameId) {
        // 模拟默认配置
        GameConfig defaultConfig = new GameConfig();
        defaultConfig.setGameId(gameId);
        defaultConfig.setGameName("Default Game");
        defaultConfig.setDescription("Standard game configuration");
        return configStore.getOrDefault(gameId, defaultConfig);
    }

    public GameConfig save(GameConfig config) {
        configStore.put(config.getGameId(), config);
        return config;
    }
}

// --- 工具类代码 ---
package com.gamestudio.dashboard.util;

import org.springframework.stereotype.Component;

/**
 * XSS过滤器（存在设计缺陷）
 * 仅去除空格，未进行HTML实体编码
 */
@Component
public class XssFilter {
    /**
     * 清理用户输入（存在误导性安全措施）
     * @param input 用户输入
     * @return 清理后的字符串
     */
    public String clean(String input) {
        if (input == null) return "";
        
        // 仅去除空格（存在安全隐患）
        return input.replaceAll("\\\\s+", "");
    }
}

// --- Thymeleaf模板片段（config-confirm.html） ---
// <div th:if="${not #strings.isEmpty(successMessage)}">
//     <p th:text="${successMessage}"></p> <!-- 漏洞触发点 -->
// </div>

// --- 模型类代码 ---
package com.gamestudio.dashboard.model;

import lombok.Data;

/**
 * 游戏配置模型
 */
@Data
public class GameConfig {
    private String gameId;
    private String gameName;
    private String description;
}