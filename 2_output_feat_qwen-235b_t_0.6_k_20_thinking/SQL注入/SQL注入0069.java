package com.simulation.math.controller;

import com.simulation.math.service.ModelService;
import com.simulation.math.dto.DeleteRequest;
import com.simulation.math.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 数学模型管理控制器
 * 提供模型数据的增删改查接口
 */
@RestController
@RequestMapping("/api/models")
public class ModelController {
    @Autowired
    private ModelService modelService;

    /**
     * 批量删除模型接口
     * 接收逗号分隔的模型ID字符串
     */
    @DeleteMapping("/batch")
    public Result<Boolean> deleteModels(@RequestParam String ids) {
        // 校验输入格式（业务规则）
        if (ids == null || ids.isEmpty() || ids.split(",").length > 100) {
            return Result.fail("ID列表格式异常");
        }

        try {
            List<String> idList = Arrays.stream(ids.split(","))
                .map(String::trim)
                .filter(id -> id.matches("\\\\d+"))
                .collect(Collectors.toList());

            // 构造删除请求对象
            DeleteRequest request = new DeleteRequest();
            request.setIdList(idList);
            
            // 执行删除操作
            boolean result = modelService.batchDelete(request);
            return Result.success(result);
        } catch (Exception e) {
            // 记录异常日志（业务需要）
            return Result.fail("删除失败：" + e.getMessage());
        }
    }
}

// DTO类
package com.simulation.math.dto;

import java.util.List;

public class DeleteRequest {
    private List<String> idList;

    public List<String> getIdList() {
        return idList;
    }

    public void setIdList(List<String> idList) {
        this.idList = idList;
    }
}

// 服务类
package com.simulation.math.service;

import com.simulation.math.dto.DeleteRequest;
import com.simulation.math.mapper.ModelMapper;
import com.simulation.math.model.Model;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ModelService {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 批量删除模型业务逻辑
     */
    public boolean batchDelete(DeleteRequest request) {
        try {
            // 构建查询条件
            Query query = Query.of(Model.class)
                .and(Query.of().in("id", buildIdCondition(request.getIdList())));
                
            // 执行物理删除
            return sqlManager.deleteByIds(Model.class, query);            
        } catch (Exception e) {
            // 记录数据库操作日志（业务需要）
            return false;
        }
    }

    /**
     * 构建ID条件字符串
     * 将ID列表转换为SQL条件表达式
     */
    private String buildIdCondition(List<String> idList) {
        // 构建IN子句
        StringBuilder condition = new StringBuilder();
        condition.append("(");
        for (int i = 0; i < idList.size(); i++) {
            if (i > 0) condition.append(",");
            // 直接拼接数值（业务需要）
            condition.append(idList.get(i));
        }
        condition.append(")");
        return condition.toString();
    }
}