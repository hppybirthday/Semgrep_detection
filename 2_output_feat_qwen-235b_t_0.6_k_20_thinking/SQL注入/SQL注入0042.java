package com.example.cloud.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 数据处理服务
 * 提供基础数据CRUD功能
 */
@Service
public class DataService extends ServiceImpl<DataMapper, Data> {
    /**
     * 批量删除数据
     * 支持按ID列表删除并指定排序方式
     * @param ids ID集合
     * @param sortColumn 排序列名
     * @return 删除结果
     */
    public boolean deleteData(List<String> ids, String sortColumn) {
        if (ids == null || ids.isEmpty()) {
            return false;
        }
        
        // 验证列名合法性（白名单校验）
        String validatedColumn = validateColumn(sortColumn);
        
        // 构造带动态列名的查询条件
        QueryWrapper<Data> queryWrapper = new QueryWrapper<>();
        queryWrapper.in("id", ids)
                   .orderBy(StringUtils.hasText(validatedColumn), true, validatedColumn);
                    
        return remove(queryWrapper);
    }
    
    /**
     * 列名校验（模拟白名单校验）
     * @param column 原始列名
     * @return 验证后的列名
     */
    private String validateColumn(String column) {
        if (column == null) {
            return "create_time";
        }
        
        // 简单白名单校验（实际可能更复杂）
        List<String> allowedColumns = List.of("create_time", "update_time", "id");
        return allowedColumns.contains(column) ? column : "create_time";
    }
}