package com.iot.device.controller;

import com.iot.device.service.DeviceDataService;
import com.iot.device.dto.DeviceDataDTO;
import com.iot.common.utils.PageUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 设备数据查询控制器
 * 提供设备监控数据的分页查询接口
 */
@RestController
@RequestMapping("/api/device/data")
public class DeviceDataController {
    @Autowired
    private DeviceDataService deviceDataService;

    @GetMapping("/list")
    @ApiOperation("分页查询设备数据")
    public PageUtils<DeviceDataDTO> list(@RequestParam Map<String, Object> params) {
        // 处理分页参数并查询数据
        return deviceDataService.queryDeviceData(params);
    }
}

// ----------------------------
// Service层代码
// ----------------------------
package com.iot.device.service;

import com.iot.device.mapper.DeviceDataMapper;
import com.iot.device.dto.DeviceDataDTO;
import com.iot.common.utils.PageUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DeviceDataService {
    @Autowired
    private DeviceDataMapper deviceDataMapper;

    public PageUtils<DeviceDataDTO> queryDeviceData(Map<String, Object> params) {
        // 验证参数合法性
        validateParams(params);
        
        // 构建查询条件
        Map<String, Object> queryCondition = buildQueryCondition(params);
        
        // 查询总记录数
        int total = deviceDataMapper.countDeviceData(queryCondition);
        
        // 分页查询数据
        List<DeviceDataDTO> dataList = deviceDataMapper.selectDeviceData(queryCondition);
        
        return new PageUtils<>(dataList, total, 
            (Integer)params.get("pageSize"), 
            (Integer)params.get("pageNum"));
    }

    private void validateParams(Map<String, Object> params) {
        // 验证必要参数存在性
        if (!params.containsKey("userId") || !params.containsKey("valueId")) {
            throw new IllegalArgumentException("Missing required parameters");
        }
    }

    private Map<String, Object> buildQueryCondition(Map<String, Object> params) {
        // 添加排序参数到查询条件
        if (params.containsKey("sort") && params.containsKey("order")) {
            params.put("orderByClause", params.get("sort") + " " + params.get("order"));
        }
        return params;
    }
}

// ----------------------------
// Mapper层代码
// ----------------------------
package com.iot.device.mapper;

import com.iot.device.dto.DeviceDataDTO;
import java.util.Map;
import java.util.List;

public interface DeviceDataMapper {
    List<DeviceDataDTO> selectDeviceData(Map<String, Object> params);
    int countDeviceData(Map<String, Object> params);
}

// ----------------------------
// MyBatis XML映射文件
// ----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.iot.device.mapper.DeviceDataMapper">
    <select id="selectDeviceData" resultType="com.iot.device.dto.DeviceDataDTO">
        SELECT * FROM device_data
        <where>
            user_id = #{userId}
            AND value_id = #{valueId}
            <if test="startTime != null">
                AND create_time >= #{startTime}
            </if>
            <if test="endTime != null">
                AND create_time <= #{endTime}
            </if>
        </where>
        <if test="orderByClause != null">
            ORDER BY ${orderByClause}
        </if>
    </select>

    <select id="countDeviceData" resultType="int">
        SELECT COUNT(*) FROM device_data
        <where>
            user_id = #{userId}
            AND value_id = #{valueId}
            <if test="startTime != null">
                AND create_time >= #{startTime}
            </if>
            <if test="endTime != null">
                AND create_time <= #{endTime}
            </if>
        </where>
    </select>
</mapper>