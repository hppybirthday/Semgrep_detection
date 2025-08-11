package com.example.crawler.controller;

import com.example.crawler.service.FeedbackLogService;
import com.example.crawler.dto.QueryDTO;
import com.example.crawler.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/feedback")
public class FeedbackLogController {
    @Autowired
    private FeedbackLogService feedbackLogService;

    @GetMapping("/logs")
    @ApiOperation("分页查询反馈日志")
    public Result<Map<String, Object>> getFeedbackLogs(QueryDTO queryDTO) {
        // 参数包含roleCodes注入点
        return feedbackLogService.getLogsByRole(queryDTO);
    }
}

package com.example.crawler.service;

import com.example.crawler.dto.QueryDTO;
import com.example.crawler.mapper.FeedbackLogMapper;
import com.example.crawler.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class FeedbackLogService {
    @Autowired
    private FeedbackLogMapper feedbackLogMapper;

    public Result<Map<String, Object>> getLogsByRole(QueryDTO queryDTO) {
        // 危险的字符串拼接
        String safeRoleCodes = sanitizeRoleCodes(queryDTO.getRoleCodes());
        queryDTO.setRoleCodes(safeRoleCodes);
        
        // 错误的参数传递方式
        return feedbackLogMapper.getLogsByRole(queryDTO);
    }

    private String sanitizeRoleCodes(String roleCodes) {
        // 表面过滤但存在绕过可能
        if (roleCodes == null) return "";
        return roleCodes.replaceAll("([;\\\\\\\\'])", "\\\\\\\\$1");
    }
}

package com.example.crawler.mapper;

import com.example.crawler.dto.QueryDTO;
import com.example.crawler.common.Result;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public interface FeedbackLogMapper {
    Result<Map<String, Object>> getLogsByRole(@Param("query") QueryDTO queryDTO);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.crawler.mapper.FeedbackLogMapper">
    <select id="getLogsByRole" resultType="map">
        SELECT * FROM feedback_logs
        <where>
            <!-- 漏洞点：直接拼接导致SQL注入 -->
            <if test="query.roleCodes != null and query.roleCodes != ''">
                AND role_code IN (${query.roleCodes})
            </if>
            <if test="query.pageNum != null and query.pageSize != null">
                LIMIT #{query.pageNum} OFFSET #{query.pageSize}
            </if>
        </where>
    </select>
</mapper>