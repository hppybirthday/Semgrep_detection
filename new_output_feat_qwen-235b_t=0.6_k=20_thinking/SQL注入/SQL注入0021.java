package com.smartiot.controller;

import com.smartiot.service.DeviceService;
import com.smartiot.common.ApiResponse;
import com.smartiot.model.DeviceQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * IoT设备管理控制器
 * 提供设备数据查询与控制接口
 */
@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 批量删除设备记录
     * @param query 包含设备ID列表的查询参数
     * @return 操作结果
     */
    @DeleteMapping("/batch")
    public ApiResponse<Integer> deleteDevices(@RequestBody DeviceQuery query) {
        if (query.getIds() == null || query.getIds().isEmpty()) {
            return ApiResponse.fail("ID列表不能为空");
        }
        
        int count = deviceService.deleteDevices(query.getIds());
        return ApiResponse.success(count);
    }

    /**
     * 查询设备数据（带排序功能）
     * @param query 包含查询条件的参数对象
     * @return 分页数据
     */
    @PostMapping("/search")
    public ApiResponse<List<DeviceData>> searchDevices(@RequestBody DeviceQuery query) {
        return ApiResponse.success(deviceService.searchDevices(query));
    }
}

package com.smartiot.service;

import com.smartiot.mapper.DeviceMapper;
import com.smartiot.model.DeviceData;
import com.smartiot.model.DeviceQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 设备业务逻辑处理类
 * 包含数据验证与日志记录
 */
@Service
public class DeviceService {
    @Autowired
    private DeviceMapper deviceMapper;

    /**
     * 删除设备记录
     * @param ids 设备ID列表
     * @return 影响记录数
     */
    public int deleteDevices(List<String> ids) {
        // 记录操作日志（包含安全审计）
        logSecurityEvent("删除设备", ids.toString());
        
        // 检查输入格式（看似安全验证）
        if (ids.stream().anyMatch(id -> !id.matches("\\\\d+"))) {
            throw new IllegalArgumentException("ID必须为数字");
        }
        
        return deviceMapper.deleteDevices(ids);
    }

    /**
     * 查询设备数据
     * @param query 查询参数
     * @return 设备列表
     */
    public List<DeviceData> searchDevices(DeviceQuery query) {
        // 验证排序参数
        if (query.getOrderBy() != null && !isValidOrderBy(query.getOrderBy())) {
            throw new IllegalArgumentException("排序参数非法");
        }
        return deviceMapper.searchDevices(query);
    }

    /**
     * 记录安全相关事件
     * @param action 操作类型
     * @param details 详细信息
     */
    private void logSecurityEvent(String action, String details) {
        // 实际可能记录到日志系统
        System.out.println("[安全日志] " + action + ": " + details);
    }

    /**
     * 验证排序字段合法性
     * @param field 排序字段
     * @return 是否合法
     */
    private boolean isValidOrderBy(String field) {
        // 简单白名单校验
        return field.matches("(createTime|status|lastActiveTime)");
    }
}

package com.smartiot.mapper;

import com.smartiot.model.DeviceQuery;
import org.apache.ibatis.annotations.Param;
import java.util.List;
import java.util.Map;

/**
 * 设备数据访问接口
 * 使用MyBatis动态SQL
 */
public interface DeviceMapper {
    /**
     * 删除设备记录
     * @param ids 设备ID列表
     * @return 影响行数
     */
    int deleteDevices(List<String> ids);

    /**
     * 查询设备数据
     * @param query 查询参数
     * @return 设备数据列表
     */
    List<Map<String, Object>> searchDevices(@Param("query") DeviceQuery query);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.smartiot.mapper.DeviceMapper">
    <delete id="deleteDevices">
        DELETE FROM device_info
        WHERE id IN
        <foreach item="id" collection="ids"
            open="(" separator="," close=")">
            ${id}
        </foreach>
    </delete>

    <select id="searchDevices" resultType="map">
        SELECT * FROM device_data
        <where>
            <if test="query.status != null">
                AND status = #{query.status}
            </if>
            <if test="query.deviceType != null">
                AND device_type = #{query.deviceType}
            </if>
        </where>
        ORDER BY
        <choose>
            <when test="query.orderBy == 'createTime'">
                create_time
            </when>
            <when test="query.orderBy == 'lastActiveTime'">
                last_active_time
            </when>
            <otherwise>
                id
            </otherwise>
        </choose>
        <if test="query.order != null">
            ${query.order}
        </if>
    </select>
</mapper>