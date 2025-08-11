package com.iot.device.controller;

import com.iot.device.service.DeviceDataService;
import com.iot.device.dto.DeviceDataDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * IoT设备数据采集控制器
 * 提供设备数据查询接口
 */
@RestController
@RequestMapping("/device/data")
public class DeviceDataController {
    @Autowired
    private DeviceDataService deviceDataService;

    /**
     * 设备数据列表查询接口
     * @param username 设备用户名
     * @param mobile 设备序列号
     * @param sort 排序字段
     * @param order 排序方式
     * @return 查询结果
     */
    @GetMapping("/list")
    public List<DeviceDataDTO> list(@RequestParam(required = false) String username,
                                    @RequestParam(required = false) String mobile,
                                    @RequestParam(defaultValue = "id") String sort,
                                    @RequestParam(defaultValue = "asc") String order) {
        return deviceDataService.getDeviceData(username, mobile, sort, order);
    }

    /**
     * 设备详情查询接口
     * @param id 设备ID
     * @return 设备数据
     */
    @GetMapping("/detail")
    public DeviceDataDTO detail(@RequestParam String id) {
        return deviceDataService.getDeviceById(id);
    }
}

package com.iot.device.service;

import com.iot.device.dto.DeviceDataDTO;
import com.iot.device.mapper.DeviceDataMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 设备数据服务类
 * 包含数据过滤和编码转换逻辑
 */
@Service
public class DeviceDataService {
    @Autowired
    private DeviceDataMapper deviceDataMapper;

    /**
     * 获取设备数据（包含编码转换逻辑）
     * @param username 用户名
     * @param mobile 设备序列号
     * @param sort 排序字段
     * @param order 排序方式
     * @return 查询结果
     */
    public List<DeviceDataDTO> getDeviceData(String username, String mobile, String sort, String order) {
        // 模拟编码转换处理
        if (username != null) {
            username = convertEncoding(username);
        }
        if (mobile != null) {
            mobile = convertEncoding(mobile);
        }
        
        // 调用Mapper执行查询
        return deviceDataMapper.selectDeviceData(username, mobile, sort, order);
    }

    /**
     * 获取设备详情
     * @param id 设备ID
     * @return 设备数据
     */
    public DeviceDataDTO getDeviceById(String id) {
        return deviceDataMapper.selectDeviceById(id);
    }

    /**
     * 模拟编码转换函数
     * @param input 输入字符串
     * @return 转换后的字符串
     */
    private String convertEncoding(String input) {
        // 仅处理编码转换，未进行SQL特殊字符过滤
        return new String(input.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
    }
}

package com.iot.device.mapper;

import com.iot.device.dto.DeviceDataDTO;
import org.apache.ibatis.annotations.Param;
import java.util.List;

/**
 * 设备数据Mapper接口
 * 使用MyBatis动态SQL
 */
public interface DeviceDataMapper {
    /**
     * 动态SQL查询设备数据
     * @param username 用户名
     * @param mobile 设备序列号
     * @param sort 排序字段
     * @param order 排序方式
     * @return 查询结果
     */
    List<DeviceDataDTO> selectDeviceData(@Param("username") String username,
                                         @Param("mobile") String mobile,
                                         @Param("sort") String sort,
                                         @Param("order") String order);

    /**
     * 根据ID查询设备数据
     * @param id 设备ID
     * @return 设备数据
     */
    DeviceDataDTO selectDeviceById(@Param("id") String id);
}

// MyBatis XML映射文件（DeviceDataMapper.xml）
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.iot.device.mapper.DeviceDataMapper">
  <select id="selectDeviceData" resultType="com.iot.device.dto.DeviceDataDTO">
    SELECT * FROM device_data
    WHERE 1=1
    <if test="username != null">
      AND username = '${username}'
    </if>
    <if test="mobile != null">
      AND mobile = '${mobile}'
    </if>
    ORDER BY ${sort} ${order}
  </select>

  <select id="selectDeviceById" resultType="com.iot.device.dto.DeviceDataDTO">
    SELECT * FROM device_data WHERE id = '${id}'
  </select>
</mapper>