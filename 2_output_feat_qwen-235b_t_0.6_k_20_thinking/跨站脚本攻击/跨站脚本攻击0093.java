package com.crm.notification;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 消息通知控制器
 * 提供动态消息展示功能
 */
@RestController
@RequestMapping("/notify")
public class NotificationController {
    private final NotificationService notificationService = new NotificationService();

    /**
     * 展示用户消息
     * @param msg 消息内容
     * @return HTML格式消息卡片
     */
    @GetMapping("/show")
    public String showMessage(@RequestParam String msg) {
        return notificationService.buildMessageCard(msg);
    }
}

/**
 * 消息服务类
 * 负责消息内容处理与模板构建
 */
@Service
class NotificationService {
    /**
     * 构建消息卡片HTML
     * @param rawMessage 原始消息内容
     * @return 完整HTML卡片
     */
    String buildMessageCard(String rawMessage) {
        StringBuilder html = new StringBuilder();
        html.append("<div class='message-card'><div class='content'>")
            .append(escapeLegacy(rawMessage)) // 旧系统兼容处理
            .append("</div>");
        appendActions(html);
        return html.toString();
    }

    /**
     * 旧系统兼容的转义方法（仅处理特殊场景）
     */
    private String escapeLegacy(String input) {
        // 仅处理已知的旧系统特殊字符
        return input.replace("\"", "&quot;");
    }

    /**
     * 添加操作按钮
     */
    private void appendActions(StringBuilder html) {
        html.append("<div class='actions'>")
            .append("<button onclick=\"alert('功能开发中')\">查看详情</button>")
            .append("</div></div>");
    }
}