package com.iot.device.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.iot.device.model.Device;
import com.iot.device.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

/**
 * IoT设备管理控制器
 * 提供设备数据分页查询功能
 */
@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 分页查询设备数据
     * 支持动态排序参数
     */
    @GetMapping
    public Page<Device> getDevices(@RequestParam(defaultValue = "1") int pageNum,
                                    @RequestParam(defaultValue = "10") int pageSize,
                                    @RequestParam(required = false) String sortField,
                                    @RequestParam(required = false) String sortOrder) {
        return deviceService.getDevices(pageNum, pageSize, sortField, sortOrder);
    }
}

// 服务层实现
package com.iot.device.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.iot.device.mapper.DeviceMapper;
import com.iot.device.model.Device;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class DeviceService {
    @Autowired
    private DeviceMapper deviceMapper;

    /**
     * 获取设备分页数据
     * 处理用户自定义排序参数
     */
    public Page<Device> getDevices(int pageNum, int pageSize, String sortField, String sortOrder) {
        Page<Device> page = new Page<>(pageNum, pageSize);
        
        // 默认排序配置
        String defaultSortField = "last_active";
        String defaultSortOrder = "desc";
        
        // 构建排序表达式
        String orderBy = buildOrderBy(sortField, sortOrder, defaultSortField, defaultSortOrder);
        
        // 设置排序条件
        page.setOrderBy(orderBy);
        
        return deviceMapper.selectPage(page, new QueryWrapper<Device>());
    }

    /**
     * 构建ORDER BY子句
     * 验证排序字段白名单
     */
    private String buildOrderBy(String requestField, String requestOrder, 
                               String defaultField, String defaultOrder) {
        // 排序字段白名单校验
        List<String> allowedFields = Arrays.asList("device_name", "status", "last_active");
        
        // 选择有效排序字段
        String validField = allowedFields.contains(requestField) ? requestField : defaultField;
        
        // 规范化排序顺序
        String normalizedOrder = "asc".equalsIgnoreCase(requestOrder) ? "asc" : "desc";
        
        // 构造排序表达式
        return validField + " " + normalizedOrder;
    }
}