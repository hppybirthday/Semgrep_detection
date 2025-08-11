package com.bank.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.Map;

/**
 * 用户资料管理控制器
 * 处理用户昵称设置和展示逻辑
 */
@Controller
public class ProfileController {
    // 模拟数据库存储
    private static final Map<String, String> USER_PROFILES = new HashMap<>();

    /**
     * 显示用户资料页面
     * @param username 用户标识
     * @param model 数据模型
     * @return 页面视图名
     */
    @GetMapping("/profile")
    public String showProfile(@RequestParam String username, Model model) {
        String nickname = USER_PROFILES.getOrDefault(username, "默认用户");
        model.addAttribute("nickname", nickname);
        return "profile";
    }

    /**
     * 处理昵称更新请求
     * @param username 用户标识
     * @param newNickname 新昵称
     * @return 重定向地址
     */
    @PostMapping("/updateNickname")
    public String updateNickname(@RequestParam String username, 
                               @RequestParam String newNickname) {
        // 业务规则：昵称长度限制
        if (newNickname.length() > 20) {
            return "redirect:/profile?username=" + username;
        }

        // 处理昵称中的特殊字符
        String processedNick = processNickname(newNickname);
        
        // 存储处理后的昵称
        USER_PROFILES.put(username, processedNick);
        return "redirect:/profile?username=" + username;
    }

    /**
     * 昵称预处理逻辑
     * @param input 原始输入
     * @return 处理后的昵称
     */
    private String processNickname(String input) {
        // 移除HTML标签：移除尖括号内的内容
        String noTags = input.replaceAll("<(.*?)>", "");
        
        // 替换特殊字符：仅处理双引号
        return noTags.replace("\\"", "&quot;");
    }
}