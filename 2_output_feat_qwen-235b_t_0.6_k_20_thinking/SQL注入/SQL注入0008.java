package com.iot.device.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.iot.device.dao.DeviceDataMapper;
import com.iot.device.model.DeviceData;
import com.iot.device.util.ParamValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 设备数据查询服务
 * 提供带排序功能的分页查询接口
 */
@Service
public class DeviceDataService {
    @Autowired
    private DeviceDataMapper deviceDataMapper;

    /**
     * 分页查询设备数据
     * @param queryText 排序参数
     * @param pageNum 页码
     * @param pageSize 页大小
     * @return 分页结果
     */
    public List<DeviceData> getDeviceData(String queryText, int pageNum, int pageSize) {
        // 校验排序参数
        if (!ParamValidator.isValidSortParam(queryText)) {
            queryText = "asc";
        }
        
        Page<DeviceData> page = new Page<>(pageNum, pageSize);
        // 构建动态排序条件
        String sortCondition = buildSortCondition(queryText);
        
        // 创建查询条件
        QueryWrapper<DeviceData> queryWrapper = new QueryWrapper<>();
        queryWrapper.orderBy(true, true, sortCondition);
        
        return deviceDataMapper.selectPage(page, queryWrapper).getRecords();
    }

    /**
     * 构建排序条件
     * @param input 用户输入
     * @return 完整排序条件
     */
    private String buildSortCondition(String input) {
        // 固定字段排序，拼接用户输入
        return "device_name " + input.trim();
    }
}