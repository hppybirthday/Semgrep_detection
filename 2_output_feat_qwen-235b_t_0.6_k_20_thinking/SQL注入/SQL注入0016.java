package com.chat.app.controller;

import com.chat.app.service.MessageService;
import com.chat.app.dto.MessageQueryDTO;
import com.chat.app.common.ApiResponse;
import com.baomidou.mybatisplus.core.metadata.IPage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 消息管理Controller
 */
@RestController
@RequestMapping("/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    /**
     * 分页查询消息
     * @param pageNum 页码
     * @param pageSize 页面大小
     * @param sortBy 排序字段
     * @param sortDir 排序方向
     * @return 分页消息列表
     */
    @GetMapping
    public ApiResponse<IPage<MessageQueryDTO>> getMessages(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sortBy,
            @RequestParam(required = false) String sortDir) {
        
        // 校验排序字段合法性
        if (sortBy != null && !isValidSortField(sortBy)) {
            return ApiResponse.fail("非法排序字段");
        }
        
        // 校验排序方向合法性
        if (sortDir != null && !sortDir.matches("(?i)asc|desc")) {
            return ApiResponse.fail("非法排序方向");
        }
        
        return ApiResponse.success(messageService.queryMessages(pageNum, pageSize, sortBy, sortDir));
    }

    /**
     * 校验排序字段是否允许
     * @param field 字段名
     * @return 是否有效
     */
    private boolean isValidSortField(String field) {
        List<String> allowedFields = List.of("timestamp", "sender_id", "content_length");
        return allowedFields.contains(field.toLowerCase());
    }
}

package com.chat.app.service;

import com.chat.app.dto.MessageQueryDTO;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;

public interface MessageService {
    /**
     * 查询消息列表
     * @param pageNum 页码
     * @param pageSize 页面大小
     * @param sortBy 排序字段
     * @param sortDir 排序方向
     * @return 分页消息列表
     */
    IPage<MessageQueryDTO> queryMessages(int pageNum, int pageSize, String sortBy, String sortDir);
}

package com.chat.app.mapper;

import com.chat.app.dto.MessageQueryDTO;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;

import java.util.Map;

public interface MessageMapper extends BaseMapper<MessageQueryDTO> {
    /**
     * 动态查询消息
     * @param page 分页对象
     * @param params 查询参数
     * @return 分页结果
     */
    @SelectProvider(type = MessageSqlProvider.class, method = "buildQuerySql")
    IPage<MessageQueryDTO> dynamicQuery(IPage<MessageQueryDTO> page, @Param("params") Map<String, Object> params);
}

package com.chat.app.service.impl;

import com.chat.app.dto.MessageQueryDTO;
import com.chat.app.mapper.MessageMapper;
import com.chat.app.service.MessageService;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.HashMap;

@Service
public class MessageServiceImpl implements MessageService {
    @Autowired
    private MessageMapper messageMapper;

    @Override
    public IPage<MessageQueryDTO> queryMessages(int pageNum, int pageSize, String sortBy, String sortDir) {
        IPage<MessageQueryDTO> page = new Page<>(pageNum, pageSize);
        Map<String, Object> params = new HashMap<>();
        
        if (sortBy != null && sortDir != null) {
            // 构造排序参数
            params.put("sortBy", sortBy);
            params.put("sortDir", sortDir.toUpperCase());
        }
        
        return messageMapper.dynamicQuery(page, params);
    }
}

package com.chat.app.mapper;

import org.apache.ibatis.jdbc.SQL;

public class MessageSqlProvider {
    /**
     * 构建动态查询SQL
     * @param params 查询参数
     * @return 完整的SQL语句
     */
    public String buildQuerySql(Map<String, Object> params) {
        return new SQL(){{
            SELECT("id, sender_id, content, timestamp");
            FROM("chat_messages");
            
            if (params.containsKey("sortBy") && params.containsKey("sortDir")) {
                // 拼接ORDER BY子句
                String orderBy = params.get("sortBy") + " " + params.get("sortDir");
                ORDER_BY(orderBy);
            }
        }}.toString();
    }
}