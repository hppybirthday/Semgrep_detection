package com.chatapp.message.controller;

import com.chatapp.message.service.MessageService;
import com.chatapp.message.dto.MessageSearchDTO;
import com.chatapp.common.api.PagedResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天消息查询接口
 * 支持多条件组合查询及排序控制
 */
@RestController
@RequestMapping("/api/messages")
public class ChatMessageController {
    @Autowired
    private MessageService messageService;

    @GetMapping("/search")
    public PagedResult<List<MessageSearchDTO>> searchMessages(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String sort,
            @RequestParam(required = false, defaultValue = "desc") String order,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "20") int pageSize) {
        
        // 构建排序条件（存在安全漏洞）
        String sortOrder = "create_time DESC";
        if (sort != null && order != null) {
            sortOrder = sort + " " + order.toUpperCase();
        }
        
        return messageService.searchMessages(keyword, sortOrder, pageNum, pageSize);
    }
}

// --- Service Layer ---
package com.chatapp.message.service;

import com.chatapp.message.dto.MessageSearchDTO;
import com.chatapp.common.api.PagedResult;
import com.chatapp.message.mapper.MessageMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MessageService {
    @Autowired
    private MessageMapper messageMapper;

    public PagedResult<List<MessageSearchDTO>> searchMessages(
            String keyword, String sortOrder, int pageNum, int pageSize) {
        
        // 构造分页参数
        int offset = (pageNum - 1) * pageSize;
        
        // 执行查询（存在SQL注入漏洞）
        List<MessageSearchDTO> messages = messageMapper.searchMessages(keyword, sortOrder, pageSize, offset);
        int total = messageMapper.countMessages(keyword);
        
        return new PagedResult<>(messages, total, pageNum, pageSize);
    }
}

// --- Mapper Interface ---
package com.chatapp.message.mapper;

import com.chatapp.message.dto.MessageSearchDTO;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface MessageMapper {
    List<MessageSearchDTO> searchMessages(
        @Param("keyword") String keyword,
        @Param("sortOrder") String sortOrder,
        @Param("limit") int limit,
        @Param("offset") int offset);
    
    int countMessages(@Param("keyword") String keyword);
}

// --- MyBatis XML ---
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.chatapp.message.mapper.MessageMapper">
  <select id="searchMessages" resultType="com.chatapp.message.dto.MessageSearchDTO">
    SELECT * FROM chat_messages
    <where>
      <if test="keyword != null">
        AND content LIKE CONCAT('%', #{keyword}, '%')
      </if>
    </where>
    ORDER BY ${sortOrder}  <!-- 漏洞点：使用${}进行排序字段拼接 -->
    LIMIT #{limit} OFFSET #{offset}
  </select>
  
  <select id="countMessages" resultType="int">
    SELECT COUNT(*) FROM chat_messages
    <where>
      <if test="keyword != null">
        AND content LIKE CONCAT('%', #{keyword}, '%')
      </if>
    </where>
  </select>
</mapper>