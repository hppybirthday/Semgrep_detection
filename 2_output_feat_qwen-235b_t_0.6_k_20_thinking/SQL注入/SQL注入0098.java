package com.chat.app.controller;

import com.chat.app.common.api.ApiResult;
import com.chat.app.model.ChatRecord;
import com.chat.app.service.ChatService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 聊天记录查询控制器
 * 提供按角色代码分页查询功能
 */
@RestController
@RequestMapping("/chat/records")
public class ChatRecordController {
    @Autowired
    private ChatService chatService;

    /**
     * 分页查询聊天记录
     * @param roleCode 角色代码
     * @param pageNum 当前页码
     * @param pageSize 每页条数
     * @param orderField 排序字段
     * @return 分页结果
     */
    @GetMapping
    public ApiResult<List<ChatRecord>> getRecordsByRole(@RequestParam String roleCode,
                                                            @RequestParam int pageNum,
                                                            @RequestParam int pageSize,
                                                            @RequestParam String orderField) {
        // 校验参数基本格式
        if (roleCode.length() > 20 || pageNum < 1 || pageSize < 1) {
            return ApiResult.fail("参数校验失败");
        }
        
        // 构造排序条件（存在漏洞点）
        String orderBy = "";
        if (orderField != null && !orderField.isEmpty()) {
            orderBy = orderField + " DESC";
        }
        
        List<ChatRecord> records = chatService.findRecordsByRole(roleCode, pageNum, pageSize, orderBy);
        return ApiResult.success(records);
    }
}

// Service层代码
package com.chat.app.service;

import com.chat.app.mapper.ChatRecordMapper;
import com.chat.app.model.ChatRecord;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ChatService {
    @Autowired
    private ChatRecordMapper chatRecordMapper;

    public List<ChatRecord> findRecordsByRole(String roleCode, int pageNum, int pageSize, String orderBy) {
        // 设置分页并动态排序
        PageHelper.startPage(pageNum, pageSize);
        if (orderBy != null && !orderBy.isEmpty()) {
            PageHelper.orderBy(orderBy);  // 危险操作：直接拼接排序语句
        }
        
        // 查询角色相关聊天记录
        return chatRecordMapper.selectByRoleCode(roleCode);
    }
}

// Mapper接口
package com.chat.app.mapper;

import com.chat.app.model.ChatRecord;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface ChatRecordMapper {
    List<ChatRecord> selectByRoleCode(@Param("roleCode") String roleCode);
}