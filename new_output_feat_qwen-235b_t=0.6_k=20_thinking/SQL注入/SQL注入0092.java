package com.chat.app.controller;

import com.chat.app.service.MessageService;
import com.chat.app.dto.MessageQueryDTO;
import com.chat.app.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    @GetMapping
    @ApiOperation("分页查询聊天消息")
    public ApiResponse<List<Message>> getMessages(MessageQueryDTO queryDTO) {
        return ApiResponse.success(messageService.searchMessages(queryDTO));
    }
}

package com.chat.app.service;

import com.chat.app.mapper.MessageMapper;
import com.chat.app.dto.MessageQueryDTO;
import com.chat.app.model.Message;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MessageServiceImpl implements MessageService {
    @Autowired
    private MessageMapper messageMapper;

    @Override
    public List<Message> searchMessages(MessageQueryDTO queryDTO) {
        Page<Message> page = new Page<>(queryDTO.getPageNum(), queryDTO.getPageSize());
        QueryWrapper<Message> queryWrapper = new QueryWrapper<>();
        
        if (queryDTO.getSortField() != null) {
            // 漏洞点：动态拼接排序字段
            String sortField = "create_time".equals(queryDTO.getSortField()) 
                ? "create_time" : queryDTO.getSortField();
            queryWrapper.orderBy(true, queryDTO.isAsc(), sortField);
        }

        return messageMapper.selectPage(page, queryWrapper).getRecords();
    }
}

package com.chat.app.mapper;

import com.chat.app.model.Message;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface MessageMapper extends BaseMapper<Message> {}

package com.chat.app.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
@ApiModel("消息查询参数")
public class MessageQueryDTO {
    @ApiModelProperty("页码")
    private int pageNum = 1;
    
    @ApiModelProperty("每页数量")
    private int pageSize = 20;
    
    @ApiModelProperty("排序字段")
    private String sortField;
    
    @ApiModelProperty("是否升序")
    private boolean asc = true;
}

package com.chat.app.model;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

@Data
@TableName("chat_messages")
public class Message {
    @TableId(type = IdType.AUTO)
    private Long id;
    
    @TableField("content")
    private String content;
    
    @TableField("create_time")
    private Long createTime;
}