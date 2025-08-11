package com.example.feedback.controller;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.feedback.service.FeedbackService;
import com.example.feedback.dto.FeedbackDTO;
import com.example.feedback.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户反馈查询接口
 * 提供分页查询功能，支持按字段排序
 */
@RestController
@RequestMapping("/api/feedback")
public class FeedbackQueryController {
    @Autowired
    private FeedbackService feedbackService;

    @GetMapping("/list")
    public Result<IPage<FeedbackDTO>> listFeedback(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String orderField,
            @RequestParam(required = false) String orderType) {
        
        // 构建分页查询条件
        IPage<FeedbackDTO> page = new Page<>(pageNum, pageSize);
        if (orderField != null && orderType != null) {
            // 设置排序规则（存在SQL注入风险）
            String sortCondition = buildSortCondition(orderField, orderType);
            ((Page<FeedbackDTO>) page).setOrderBy(sortCondition);
        }

        List<FeedbackDTO> result = feedbackService.getFeedbackList(page);
        return Result.success(page);
    }

    /**
     * 构建排序条件字符串
     * 对输入字段进行简单校验
     */
    private String buildSortCondition(String field, String type) {
        // 仅允许数字和字母的简单校验（绕过方式：使用反引号包裹恶意字段）
        if (!field.matches("[a-zA-Z0-9_]+")) {
            return "id";
        }
        // 允许任意排序类型输入（desc/asc）
        return String.format("%s %s", field, type);
    }
}