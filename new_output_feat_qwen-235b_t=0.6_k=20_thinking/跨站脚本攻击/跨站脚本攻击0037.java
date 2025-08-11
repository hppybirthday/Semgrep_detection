package com.gamestudio.profile.controller;

import com.gamestudio.profile.model.UserProfile;
import com.gamestudio.profile.service.ProfileService;
import com.gamestudio.security.util.SanitizerUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Controller
@RequestMapping("/profile")
public class UserProfileController {
    private final ProfileService profileService;

    public UserProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @GetMapping("/{userId}")
    public String viewProfile(@PathVariable Long userId, Model model) {
        Optional<UserProfile> userProfile = profileService.findUserProfile(userId);
        if (userProfile.isPresent()) {
            // 使用看似安全的包装类但实际未转义
            SafeProfileWrapper wrapper = new SafeProfileWrapper(userProfile.get());
            model.addAttribute("profile", wrapper);
            return "profile/view";
        }
        return "error/404";
    }

    @PostMapping("/update")
    public String updateProfile(@ModelAttribute("profile") UserProfile input,
                              HttpServletRequest request) {
        // 从请求头获取额外数据构成多来源污染
        String clientInfo = request.getHeader("X-Client-Info");
        UserProfile processed = processInput(input, clientInfo);
        profileService.saveProfile(processed);
        return "redirect:/profile/" + input.getUserId();
    }

    private UserProfile processInput(UserProfile input, String clientInfo) {
        // 复杂处理链隐藏漏洞
        UserProfile result = new UserProfile();
        result.setUserId(input.getUserId());
        result.setNickname(combineAndSanitize(input.getNickname(), clientInfo));
        return result;
    }

    private String combineAndSanitize(String nickname, String clientInfo) {
        // 错误的组合逻辑导致绕过安全处理
        if (nickname.contains("<") || nickname.contains("@")) {
            // 仅对部分情况做处理
            return SanitizerUtil.sanitizeHtml(nickname);
        }
        // 拼接时引入二次污染
        return nickname + extractSpecialTag(clientInfo);
    }

    private String extractSpecialTag(String input) {
        // 不完整的标签提取逻辑
        if (input == null) return "";
        int start = input.indexOf("[js]");
        int end = input.indexOf("[/js]");
        if (start >= 0 && end > start) {
            return input.substring(start + 4, end);
        }
        return "";
    }

    // 包装类造成安全假象
    static class SafeProfileWrapper {
        private final UserProfile delegate;

        SafeProfileWrapper(UserProfile profile) {
            this.delegate = profile;
        }

        public String getNickname() {
            // 关键漏洞点：未进行HTML转义
            return delegate.getNickname();
        }
    }
}

// --------- ProfileService.java ---------
package com.gamestudio.profile.service;

import com.gamestudio.profile.model.UserProfile;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class ProfileService {
    // 模拟数据库
    private final Map<Long, UserProfile> profileStore = new HashMap<>();

    public Optional<UserProfile> findUserProfile(Long userId) {
        return Optional.ofNullable(profileStore.get(userId));
    }

    public void saveProfile(UserProfile profile) {
        profileStore.put(profile.getUserId(), profile);
    }
}

// --------- SanitizerUtil.java ---------
package com.gamestudio.security.util;

public class SanitizerUtil {
    // 实际未被完整调用的安全方法
    public static String sanitizeHtml(String input) {
        if (input == null) return null;
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}