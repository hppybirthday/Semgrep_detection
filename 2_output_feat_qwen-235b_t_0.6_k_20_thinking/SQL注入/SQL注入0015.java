package com.example.report.controller;

import com.example.report.service.UserReportService;
import com.example.report.dto.ReportDTO;
import com.example.report.common.PageResult;
import com.example.report.util.SqlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/user/report")
public class UserReportController {
    @Autowired
    private UserReportService userReportService;

    @GetMapping("list")
    public PageResult list(@RequestParam Map<String, Object> params) {
        // 提取排序参数并进行基础校验
        String sortedField = (String) params.get("sortedField");
        String sortOrder = (String) params.get("sortOrder");
        
        // 调用安全工具类处理排序字段
        if (sortedField != null && !sortedField.isEmpty()) {
            sortedField = SqlUtil.escapeOrderBySql(sortedField);
        }
        
        // 构造排序参数（存在拼接SQL片段风险）
        params.put("sortedField", sortedField);
        params.put("sortOrder", "asc".equalsIgnoreCase(sortOrder) ? "ASC" : "DESC");
        
        // 执行带动态排序的查询
        return userReportService.generateReport(params);
    }
}

// --- Service层实现 ---
package com.example.report.service;

import com.example.report.dto.ReportDTO;
import com.example.report.common.PageResult;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserReportService {
    @Autowired
    private ReportMapper reportMapper;

    public PageResult generateReport(Map<String, Object> params) {
        // 构建分页参数
        int pageNum = (int) params.getOrDefault("pageNum", 1);
        int pageSize = (int) params.getOrDefault("pageSize", 10);
        
        // 构造动态排序SQL（错误使用${}导致注入）
        String orderBy = "";
        if (params.containsKey("sortedField")) {
            orderBy = String.format("%s %s", 
                params.get("sortedField"), 
                params.get("sortOrder"));
        }
        
        // 执行MyBatis Plus分页查询
        Page<ReportDTO> page = new Page<>(pageNum, pageSize);
        return reportMapper.selectUserReport(page, orderBy);
    }
}

// --- Mapper接口 ---
package com.example.report.mapper;

import com.example.report.dto.ReportDTO;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface ReportMapper extends BaseMapper<ReportDTO> {
    @Select({"<script>",
      "SELECT * FROM user_activity_log",
      "<if test='orderBy != null and !orderBy.isEmpty()'>",
        "ORDER BY ${orderBy}",
      "</if>",
      "</script>"})
    List<ReportDTO> selectUserReport(Page<ReportDTO> page, @Param("orderBy") String orderBy);
}

// --- 工具类实现 ---
package com.example.report.util;

public class SqlUtil {
    /**
     * 对ORDER BY参数进行基础转义
     * 过滤特殊符号防止SQL注入
     */
    public static String escapeOrderBySql(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        
        // 替换常见特殊字符
        String result = input.replaceAll("[;'"]", "");
        
        // 限制长度防止畸形输入
        return result.length() > 64 ? result.substring(0, 64) : result;
    }
}