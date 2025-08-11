package com.example.iot.device.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.iot.device.mapper.DeviceFeedbackMapper;
import com.example.iot.device.model.DeviceFeedback;
import com.example.iot.device.util.QuerySanitizer;
import com.example.iot.device.dto.FeedbackQuery;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

@Service
public class DeviceFeedbackService extends ServiceImpl<DeviceFeedbackMapper, DeviceFeedback> {
    private final DeviceFeedbackMapper feedbackMapper;

    public DeviceFeedbackService(DeviceFeedbackMapper feedbackMapper) {
        this.feedbackMapper = feedbackMapper;
    }

    public List<DeviceFeedback> queryFeedbacks(FeedbackQuery query) {
        QueryWrapper<DeviceFeedback> wrapper = new QueryWrapper<>();
        
        if (StringUtils.hasText(query.getDeviceId())) {
            // 使用自定义过滤器处理输入（存在绕过漏洞）
            String sanitizedId = QuerySanitizer.sanitizeDeviceId(query.getDeviceId());
            wrapper.like("device_id", sanitizedId);
        }
        
        if (query.getSeverity() != null) {
            wrapper.eq("severity_level", query.getSeverity());
        }
        
        if (StringUtils.hasText(query.getCustomFilter())) {
            // 危险：直接拼接自定义SQL条件（漏洞点）
            String unsafeFilter = processCustomFilter(query.getCustomFilter());
            wrapper.apply(unsafeFilter);
        }
        
        // 间接触发SQL注入（跨方法调用）
        return feedbackMapper.selectList(wrapper);
    }

    private String processCustomFilter(String filter) {
        if (filter.contains("device_status")) {
            // 错误的正则替换（可被绕过）
            return filter.replaceAll("(\\s+)(OR|AND)(\\s+)(device_status)(\\s*=)", "");
        }
        return filter;
    }
}

// ----------------------------

package com.example.iot.device.util;

public class QuerySanitizer {
    // 存在漏洞的过滤实现（可被编码绕过）
    public static String sanitizeDeviceId(String input) {
        return input.replace("'", "'""'); // 错误的转义处理
    }
}

// ----------------------------

package com.example.iot.device.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.iot.device.model.DeviceFeedback;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface DeviceFeedbackMapper extends BaseMapper<DeviceFeedback> {
    List<DeviceFeedback> selectListWithCustomFilter(String customFilter);
}

// ----------------------------

package com.example.iot.device.model;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

@Data
@TableName("device_feedback_records")
public class DeviceFeedback {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String deviceId;
    private Integer severityLevel;
    private String feedbackDetail;
    private Integer deviceStatus;
}

// ----------------------------

package com.example.iot.device.dto;

import lombok.Data;

@Data
public class FeedbackQuery {
    private String deviceId;
    private Integer severity;
    private String customFilter; // 恶意输入示例："1=1 OR device_status=1 UNION SELECT * FROM users--"
}