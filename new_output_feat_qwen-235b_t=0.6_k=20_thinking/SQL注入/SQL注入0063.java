package com.chat.app.controller;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.model.Message;
import com.chat.app.service.MessageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 聊天消息管理Controller
 * 提供基于排序参数的分页查询接口
 */
@RestController
@RequestMapping("/chat/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    /**
     * 分页查询聊天记录
     * 攻击者可通过sort/order参数注入恶意SQL
     * 示例攻击请求:
     * /chat/messages/list?pageNum=1&pageSize=10&sort=username%20;+DROP+TABLE+messages--&order=ASC
     */
    @GetMapping("/list")
    public Map<String, Object> listMessages(
            @RequestParam("pageNum") int pageNum,
            @RequestParam("pageSize") int pageSize,
            @RequestParam(value = "sort", required = false) String sort,
            @RequestParam(value = "order", required = false) String order) {
        
        // 错误的防御尝试：尝试过滤特殊字符但可被绕过
        if (sort != null) {
            sort = sort.replaceAll("[;'"]", ""); // 仅过滤部分特殊字符
        }
        
        IPage<Message> result = messageService.getMessages(pageNum, pageSize, sort, order);
        
        Map<String, Object> response = new HashMap<>();
        response.put("data", result.getRecords());
        response.put("total", result.getTotal());
        return response;
    }
}

package com.chat.app.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.mapper.MessageMapper;
import com.chat.app.model.Message;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 消息服务层
 * 存在SQL注入漏洞的关键位置：ORDER BY子句拼接
 */
@Service
public class MessageService {
    @Autowired
    private MessageMapper messageMapper;

    /**
     * 获取分页消息数据
     * 漏洞点：直接拼接ORDER BY子句
     */
    public IPage<Message> getMessages(int pageNum, int pageSize, String sort, String order) {
        // 构造分页对象
        Page<Message> page = new Page<>(pageNum, pageSize);
        
        // 构造排序条件 - 存在漏洞的关键点
        if (sort != null && order != null) {
            String orderByClause = formatOrderBy(sort, order);
            page.setOrderBySql(orderByClause); // 直接拼接用户输入
        }
        
        return messageMapper.selectPage(page, null);
    }

    /**
     * 错误的防御逻辑：看似处理排序字段但存在漏洞
     * 实际未进行有效白名单校验
     */
    private String formatOrderBy(String sortField, String sortOrder) {
        // 错误的字段验证逻辑
        if ("timestamp".equalsIgnoreCase(sortField)) {
            sortField = "create_time"; // 字段名转换
        }
        
        // 未校验排序方向参数，允许注入
        return String.format("%s %s", sortField, sortOrder);
    }
}

package com.chat.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.chat.app.model.Message;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface MessageMapper extends BaseMapper<Message> {
}

package com.chat.app.model;

import lombok.Data;

/**
 * 聊天消息实体类
 */
@Data
public class Message {
    private Long id;
    private String username;
    private String content;
    private Long createTime;
}

package com.chat.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * MyBatis Plus配置类（简化示例）
 */
@Configuration
public class MyBatisPlusConfig {
    // 实际应配置分页插件等
}
