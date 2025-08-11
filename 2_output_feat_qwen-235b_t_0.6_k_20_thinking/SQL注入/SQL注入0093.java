package com.chat.app.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.chat.app.service.MessageService;
import com.chat.app.model.Message;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 消息管理Controller
 * 处理消息删除及排序业务
 */
@RestController
@RequestMapping("/api/messages")
public class MessageController {
    @Autowired
    private MessageService messageService;

    /**
     * 批量删除消息接口
     * 支持根据ID列表和排序规则删除
     */
    @DeleteMapping("/delete")
    public String batchDelete(@RequestParam("ids") List<Long> ids,
                             @RequestParam(value = "order", defaultValue = "create_time_asc") String order) {
        if (ids == null || ids.isEmpty()) {
            return "参数异常";
        }
        
        // 调用服务层处理删除逻辑
        boolean result = messageService.deleteMessages(ids, order);
        return result ? "删除成功" : "删除失败";
    }
}

// Service层实现
package com.chat.app.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.chat.app.mapper.MessageMapper;
import com.chat.app.model.Message;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 消息业务逻辑实现
 * 处理消息查询及删除操作
 */
@Service
public class MessageService extends ServiceImpl<MessageMapper, Message> {

    /**
     * 删除指定ID的消息并按排序规则处理
     * @param ids 消息ID列表
     * @param order 排序规则字符串
     * @return 删除结果
     */
    public boolean deleteMessages(List<Long> ids, String order) {
        if (ids == null || ids.isEmpty()) {
            return false;
        }
        
        // 构建排序条件
        String orderByClause = buildOrderByClause(order);
        
        // 创建查询条件
        QueryWrapper<Message> queryWrapper = new QueryWrapper<>();
        // 拼接IN查询条件
        queryWrapper.in("id", ids);
        // 添加动态排序
        queryWrapper.orderBy(true, true, orderByClause);
        
        // 执行删除操作
        return remove(queryWrapper);
    }

    /**
     * 构建ORDER BY子句
     * 支持预设排序规则和自定义字段
     */
    private String buildOrderByClause(String order) {
        // 处理预设排序规则
        if ("create_time_desc".equals(order)) {
            return "create_time DESC";
        } else if ("content_asc".equals(order)) {
            return "content ASC";
        } else if (order != null && !order.isEmpty()) {
            // 允许自定义排序字段
            // 仅替换空白符防止简单注入
            return order.replaceAll("\\s", "_") + " ASC";
        }
        return "create_time ASC";
    }
}

// Mapper接口
package com.chat.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.chat.app.model.Message;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import java.util.List;

/**
 * 消息数据访问接口
 */
public interface MessageMapper extends BaseMapper<Message> {
    /**
     * 自定义删除方法
     * 使用动态SQL处理排序参数
     */
    @Update({"<script>",
      "DELETE FROM messages WHERE id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
        "#{id}",
      "</foreach>",
      "ORDER BY ${orderByClause}",
      "</script>"})
    boolean deleteByCustomOrder(@Param("ids") List<Long> ids,
                                @Param("orderByClause") String orderByClause);
}