package com.bank.financial.controller;

import com.bank.financial.service.UserService;
import com.bank.financial.dto.UserProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(path = "/api/user", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {
    
    @Autowired
    private UserService userService;
    
    /**
     * 用户资料更新接口
     * @param userId 用户唯一标识
     * @param nickname 用户昵称
     * @return 操作结果
     */
    @PostMapping("/update")
    public Map<String, Object> updateUserProfile(@RequestParam String userId, 
                                               @RequestParam String nickname) {
        // 构造响应数据结构
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 业务逻辑校验
            if (userId == null || nickname.length() > 32) {
                response.put("status", "error");
                response.put("message", "参数校验失败");
                return response;
            }
            
            // 调用服务层更新数据
            UserProfile profile = userService.updateUserProfile(userId, nickname);
            
            // 构建成功响应
            response.put("status", "success");
            response.put("data", formatUserProfile(profile));
            
        } catch (Exception e) {
            // 异常信息直接返回
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        
        return response;
    }
    
    /**
     * 格式化用户资料数据
     */
    private Map<String, Object> formatUserProfile(UserProfile profile) {
        Map<String, Object> data = new HashMap<>();
        data.put("userId", profile.getUserId());
        data.put("nickname", profile.getNickname());
        data.put("lastLogin", profile.getLastLoginTime());
        return data;
    }
}