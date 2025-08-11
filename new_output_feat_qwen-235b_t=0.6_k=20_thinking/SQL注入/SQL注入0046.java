package com.example.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.controller.dto.DeleteRequest;
import com.example.mapper.VulnerableMapper;
import com.example.model.VulnerableEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

@Service
public class VulnerableService extends ServiceImpl<VulnerableMapper, VulnerableEntity> {
    private static final String[] ALLOWED_COLUMNS = {"id", "name", "created_at"};

    public List<VulnerableEntity> getSortedByDynamicColumn(String mainId) {
        Page<VulnerableEntity> page = new Page<>(1, 10);
        // 错误地将用户输入直接拼接到ORDER BY
        page.orderByDesc(mainId);  // 漏洞点：直接拼接列名
        return baseMapper.selectPage(page, null).getRecords();
    }

    public boolean batchDelete(DeleteRequest request) {
        if (request.getIds() == null || request.getIds().isEmpty()) {
            return false;
        }
        
        // 错误的输入验证：仅检查是否为数字
        for (String id : request.getIds()) {
            if (!id.matches("\\\\d+")) {
                return false;
            }
        }
        
        // 二次错误：将验证过的ID列表转换为字符串拼接
        String idList = String.join(",", request.getIds());
        return baseMapper.deleteByCustomSql(idList) > 0;
    }

    // 错误的列名验证方法（存在逻辑漏洞）
    private boolean isValidColumn(String column) {
        for (String allowed : ALLOWED_COLUMNS) {
            if (allowed.equals(column)) {
                return true;
            }
        }
        return false;
    }
}

// Mapper接口
package com.example.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.model.VulnerableEntity;
import java.util.List;

public interface VulnerableMapper extends BaseMapper<VulnerableEntity> {
    @Select({"<script>",
      "SELECT * FROM vulnerable_table WHERE id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
        "#{id}",
      "</foreach>",
      "ORDER BY ${@com.example.utils.SqlSanitizer.sanitize(mainId)}",  // 错误的参数化
    "</script>"})
    List<VulnerableEntity> selectByDynamicOrder(@Param("mainId") String mainId);

    // 错误的批量删除方法
    @Select("DELETE FROM vulnerable_table WHERE id IN (${idList})")  // 漏洞点：使用${}拼接
    int deleteByCustomSql(@Param("idList") String idList);
}

// Controller层
package com.example.controller;

import com.example.service.VulnerableService;
import com.example.controller.dto.DeleteRequest;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/vulnerable")
public class VulnerableController {
    private final VulnerableService vulnerableService;

    public VulnerableController(VulnerableService vulnerableService) {
        this.vulnerableService = vulnerableService;
    }

    @GetMapping("/sorted")
    public List<?> getSorted(@RequestParam String mainId) {
        // 错误地直接传递用户输入到业务层
        return vulnerableService.getSortedByDynamicColumn(mainId);
    }

    @PostMapping("/delete/batch")
    public boolean batchDelete(@RequestBody DeleteRequest request) {
        // 看似严格的验证实际存在绕过可能
        return vulnerableService.batchDelete(request);
    }
}

// DTO类
package com.example.controller.dto;

import java.util.List;

public class DeleteRequest {
    private List<String> ids;

    public List<String> getIds() {
        return ids;
    }

    public void setIds(List<String> ids) {
        this.ids = ids;
    }
}

// 错误的SQL工具类
package com.example.utils;

public class SqlSanitizer {
    // 错误的净化方法：无法防御多层编码攻击
    public static String sanitize(String input) {
        if (input == null) return "";
        return input.replace("--", "");  // 简单替换无法防御
    }
}