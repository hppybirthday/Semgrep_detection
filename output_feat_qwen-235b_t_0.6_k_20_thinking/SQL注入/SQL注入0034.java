package com.chat.example.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.example.model.Message;
import com.chat.example.service.MessageService;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    @GetMapping
    public Page<Message> getMessages(@RequestParam String queryText, 
                                      @RequestParam(defaultValue = "1") int pageNum,
                                      @RequestParam(defaultValue = "10") int pageSize,
                                      @RequestParam String orderField) {
        // 模拟防御式编程中的错误认知：认为PageHelper已安全处理
        PageHelper.startPage(pageNum, pageSize);
        PageHelper.orderBy(orderField); // 危险操作：直接拼接排序字段
        
        // 使用MyBatis Plus构造查询条件
        QueryWrapper<Message> wrapper = new QueryWrapper<>();
        if (queryText != null && !queryText.isEmpty()) {
            // 正确的参数化查询示例（防御式编程）
            wrapper.like("content", queryText);
        }
        
        // 执行查询
        List<Message> messages = messageService.list(wrapper);
        return (Page<Message>) Page.of(messages, pageNum, pageSize);
    }
}

// Service层示例（简化版）
package com.chat.example.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.chat.example.mapper.MessageMapper;
import com.chat.example.model.Message;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MessageService extends ServiceImpl<MessageMapper, Message> {
    public List<Message> searchMessages(String queryText, String orderField) {
        // 构造动态SQL时错误地拼接orderField
        return query().like(queryText != null, "content", queryText)
                     .orderBy(orderField != null, true, orderField) // 危险操作
                     .list();
    }
}

// Mapper接口
package com.chat.example.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.chat.example.model.Message;
import java.util.List;

public interface MessageMapper extends BaseMapper<Message> {
    @Select("SELECT * FROM messages WHERE content LIKE CONCAT('%',#{queryText},'%') ORDER BY ${orderField}")
    List<Message> searchWithOrder(@Param("queryText") String queryText, 
                                 @Param("orderField") String orderField);
}