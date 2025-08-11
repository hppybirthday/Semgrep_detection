package com.example.dataservice;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.dataservice.mapper.DataMapper;
import com.example.dataservice.model.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.Arrays;

/**
 * 数据清理服务
 * 提供旧数据清理功能
 */
@Service
public class DataCleanService {
    @Autowired
    private DataMapper dataMapper;

    /**
     * 清理指定ID的数据
     * @param aids 需要清理的数据ID数组
     */
    public void cleanOldData(String[] aids) {
        if (aids == null || aids.length == 0) {
            throw new IllegalArgumentException("参数不能为空");
        }
        
        String condition = buildCondition(aids);
        // 执行数据清理操作
        dataMapper.delete(new QueryWrapper<Data>().apply(condition));
    }

    /**
     * 构建删除条件
     * @param aids 原始ID数组
     * @return SQL条件字符串
     */
    private String buildCondition(String[] aids) {
        String inClause = convertToINClause(aids);
        return "id IN (" + inClause + ")";
    }

    /**
     * 转换数组为IN子句格式
     * @param aids 字符串数组参数
     * @return 逗号分隔的字符串
     */
    private String convertToINClause(String[] aids) {
        // 将数组转换为逗号分隔的字符串
        return String.join(",", Arrays.asList(aids));
    }
}