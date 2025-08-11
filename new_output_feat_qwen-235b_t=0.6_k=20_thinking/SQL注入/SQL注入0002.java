package com.chatapp.controller;

import com.chatapp.service.ChatService;
import com.chatapp.model.ChatRecord;
import com.chatapp.common.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天记录查询控制器
 * 提供根据用户ID查询聊天历史的功能
 */
@RestController
@RequestMapping("/chat")
public class ChatController {
    @Autowired
    private ChatService chatService;

    /**
     * 分页查询聊天记录
     * @param userId 用户ID
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @param sortField 排序字段
     * @param sortOrder 排序方式
     * @return 分页结果
     */
    @GetMapping("/history")
    public PageResult<List<ChatRecord>> getChatHistory(
        @RequestParam("userId") Long userId,
        @RequestParam(value = "pageNum", defaultValue = "1") int pageNum,
        @RequestParam(value = "pageSize", defaultValue = "20") int pageSize,
        @RequestParam(value = "sortField", defaultValue = "timestamp") String sortField,
        @RequestParam(value = "sortOrder", defaultValue = "DESC") String sortOrder) {
        
        List<ChatRecord> records = chatService.getChatHistory(userId, pageNum, pageSize, sortField, sortOrder);
        return PageResult.success(records);
    }
}

package com.chatapp.service;

import com.chatapp.mapper.ChatMapper;
import com.chatapp.model.ChatRecord;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 聊天记录服务层
 * 处理核心业务逻辑
 */
@Service
public class ChatService {
    @Autowired
    private ChatMapper chatMapper;

    /**
     * 获取用户聊天历史
     * @param userId 用户ID
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @param sortField 排序字段
     * @param sortOrder 排序方式
     * @return 聊天记录列表
     */
    public List<ChatRecord> getChatHistory(Long userId, int pageNum, int pageSize, String sortField, String sortOrder) {
        QueryWrapper<ChatRecord> queryWrapper = new QueryWrapper<>();
        
        // 构造查询条件
        queryWrapper.eq("user_id", userId)
                   .ge("status", 0);

        // 排序条件构造（存在漏洞点）
        if (sortField != null && !sortField.isEmpty() && 
            (sortOrder.equals("ASC") || sortOrder.equals("DESC"))) {
            queryWrapper.orderBy(true, sortOrder.equals("ASC"), sortField);
        } else {
            queryWrapper.orderByDesc("timestamp");
        }

        // 分页查询
        return chatMapper.selectPage(new Page<>(pageNum, pageSize), queryWrapper);
    }
}

package com.chatapp.mapper;

import com.chatapp.model.ChatRecord;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * 聊天记录数据访问层
 */
@Mapper
public interface ChatMapper extends BaseMapper<ChatRecord> {
}

package com.chatapp.model;

import lombok.Data;
import com.baomidou.mybatisplus.annotation.*;

/**
 * 聊天记录实体类
 */
@Data
@TableName("chat_records")
public class ChatRecord {
    @TableId(type = IdType.AUTO)
    private Long id;
    private Long userId;
    private String content;
    private Long timestamp;
    private Integer status;
    // 0-正常 1-已删除
}

package com.chatapp.common;

import lombok.Data;

/**
 * 统一分页响应封装
 */
@Data
public class PageResult<T> {
    private int code;
    private String message;
    private T data;
    private int total;
    
    public static <T> PageResult<T> success(T data) {
        PageResult<T> result = new PageResult<>();
        result.setCode(200);
        result.setMessage("success");
        result.setData(data);
        return result;
    }
}