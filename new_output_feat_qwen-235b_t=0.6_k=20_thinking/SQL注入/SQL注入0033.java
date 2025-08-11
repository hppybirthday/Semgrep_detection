package com.chat.app.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.common.ApiResponse;
import com.chat.app.model.Message;
import com.chat.app.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天消息查询控制器
 * 提供按条件分页查询功能
 */
@RestController
@RequestMapping("/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    /**
     * 分页查询聊天消息
     * 攻击者可通过sortOrder参数注入恶意SQL
     */
    @GetMapping("/list")
    public ApiResponse<Page<Message>> listMessages(
            @RequestParam(name = "senderId", required = false) Long senderId,
            @RequestParam(name = "receiverId", required = false) Long receiverId,
            @RequestParam(name = "keyword", required = false) String keyword,
            @RequestParam(name = "pageNum", defaultValue = "1") int pageNum,
            @RequestParam(name = "pageSize", defaultValue = "20") int pageSize,
            @RequestParam(name = "sortField", defaultValue = "timestamp") String sortField,
            @RequestParam(name = "sortOrder", defaultValue = "desc") String sortOrder) {

        // 构造查询条件
        QueryWrapper<Message> queryWrapper = new QueryWrapper<>();
        if (senderId != null) {
            queryWrapper.eq("sender_id", senderId);
        }
        if (receiverId != null) {
            queryWrapper.eq("receiver_id", receiverId);
        }
        if (keyword != null && !keyword.isEmpty()) {
            queryWrapper.like("content", keyword);
        }

        // 构造排序条件（存在SQL注入漏洞）
        String sanitizedSortField = sanitizeSortField(sortField);
        String sanitizedSortOrder = sanitizeSortOrder(sortOrder);
        
        // 创建分页对象
        Page<Message> page = new Page<>(pageNum, pageSize);
        // 拼接ORDER BY子句（错误地直接拼接SQL片段）
        page.setAsc("asc".equalsIgnoreCase(sanitizedSortOrder));
        
        // 执行查询
        Page<Message> resultPage = messageService.page(page, queryWrapper);
        return ApiResponse.success(resultPage);
    }

    /**
     * 白名单校验排序字段（存在绕过漏洞）
     */
    private String sanitizeSortField(String field) {
        if (field == null || field.isEmpty()) {
            return "timestamp";
        }
        // 仅允许特定字段排序
        switch (field.toLowerCase()) {
            case "timestamp":
            case "sender_id":
            case "receiver_id":
                return field;
            default:
                return "timestamp"; // 默认回退
        }
    }

    /**
     * 校验排序顺序参数（存在逻辑缺陷）
     */
    private String sanitizeSortOrder(String order) {
        if (order == null || order.isEmpty()) {
            return "desc";
        }
        // 仅允许asc/desc
        if (!"asc".equalsIgnoreCase(order) && !"desc".equalsIgnoreCase(order)) {
            return "desc"; // 默认降序
        }
        return order;
    }
}

// MessageService.java（省略实现细节）
package com.chat.app.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.chat.app.model.Message;

public interface MessageService extends IService<Message> {
    // 通过MyBatis Plus内置分页功能实现查询
}

// Message.java（实体类）
package com.chat.app.model;

import lombok.Data;

@Data
public class Message {
    private Long id;
    private Long senderId;
    private Long receiverId;
    private String content;
    private Long timestamp;
}

// ApiResponse.java（通用响应包装类）
package com.chat.app.common;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;

    public static <T> ApiResponse<T> success(T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setCode(200);
        response.setMessage("success");
        response.setData(data);
        return response;
    }

    public static <T> ApiResponse<T> failed(String message) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setCode(500);
        response.setMessage(message);
        return response;
    }
}