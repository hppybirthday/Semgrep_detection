package com.chat.app.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.common.ApiResponse;
import com.chat.app.service.MessageService;
import com.chat.app.model.Message;
import com.chat.app.util.SqlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    @GetMapping("/search")
    public ApiResponse<List<Message>> searchMessages(
            @RequestParam(required = false) String productName,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(defaultValue = "id") String sort,
            @RequestParam(defaultValue = "asc") String order) {
        
        String safeSort = SqlUtil.escapeOrderBySql(sort);
        String safeOrder = SqlUtil.escapeOrderBySql(order);
        
        Page<Message> page = messageService.search(productName, pageNum, pageSize, safeSort, safeOrder);
        return ApiResponse.success(page.getRecords());
    }
}

package com.chat.app.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.mapper.MessageMapper;
import com.chat.app.model.Message;
import com.chat.app.util.SqlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MessageService {
    @Autowired
    private MessageMapper messageMapper;

    public Page<Message> search(String productName, int pageNum, int pageSize, String sort, String order) {
        String orderBy = String.format("%s %s", sort, order);
        return messageMapper.selectPage(
            new Page<>(pageNum, pageSize),
            new QueryWrapper<Message>().like(productName != null, "content", productName)
                .orderByRaw(orderBy)
        );
    }
}

package com.chat.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.chat.app.model.Message;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface MessageMapper extends BaseMapper<Message> {}

package com.chat.app.util;

public class SqlUtil {
    public static String escapeOrderBySql(String input) {
        if (input == null) return "id";
        return input.replaceAll("[^a-zA-Z0-9_\\s]", "");
    }
}

// MyBatis Plus配置类（简化版）
package com.chat.app.config;

import com.baomidou.mybatisplus.extension.plugins.MyBatisPlusInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MyBatisConfig {
    @Bean
    public MyBatisPlusInterceptor myBatisPlusInterceptor() {
        return new MyBatisPlusInterceptor();
    }
}