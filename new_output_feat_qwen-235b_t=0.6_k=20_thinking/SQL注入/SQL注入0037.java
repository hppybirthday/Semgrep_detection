package com.iot.device.controller;

import com.iot.device.service.DeviceService;
import com.iot.device.dto.DeviceQueryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/data")
    public List<Map<String, Object>> getDeviceData(@RequestParam String mainId, @RequestParam String queryText) {
        // 对mainId进行简单非空校验，但未做内容过滤
        if (mainId == null || mainId.isEmpty()) {
            throw new IllegalArgumentException("mainId cannot be empty");
        }
        return deviceService.getDeviceData(mainId, queryText);
    }
}

package com.iot.device.service;

import com.iot.device.mapper.DeviceMapper;
import com.iot.device.dto.DeviceQueryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class DeviceService {
    @Autowired
    private DeviceMapper deviceMapper;

    public List<Map<String, Object>> getDeviceData(String mainId, String queryText) {
        // 构造动态查询条件
        DeviceQueryDTO queryDTO = new DeviceQueryDTO();
        queryDTO.setMainId(mainId);
        queryDTO.setQueryText(queryText);
        
        // 传递参数到数据层
        return deviceMapper.queryDeviceData(queryDTO);
    }
}

package com.iot.device.mapper;

import com.iot.device.dto.DeviceQueryDTO;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public interface DeviceMapper {
    List<Map<String, Object>> queryDeviceData(@Param("query") DeviceQueryDTO queryDTO);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.iot.device.mapper.DeviceMapper">
    <select id="queryDeviceData" resultType="map">
        SELECT * FROM device_data
        <where>
            <!-- 漏洞点：动态拼接列名 -->
            ${query.mainId} = #{query.queryText}
            <!-- 本应使用固定列名 + 参数化查询 -->
            <!-- 正确写法应为：device_id = #{query.queryText} -->
        </where>
    </select>
</mapper>

package com.iot.device.dto;

import lombok.Data;

@Data
public class DeviceQueryDTO {
    private String mainId;
    private String queryText;
}