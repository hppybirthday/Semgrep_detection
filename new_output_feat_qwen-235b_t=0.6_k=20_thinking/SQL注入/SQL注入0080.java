package com.iot.device.controller;

import com.iot.device.service.DeviceService;
import com.iot.device.dto.DeviceQueryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/status")
    public List<DeviceStatus> queryDeviceStatus(HttpServletRequest request) {
        String orderField = request.getParameter("orderField");
        return deviceService.getDeviceStatus(orderField);
    }
}

package com.iot.device.service;

import com.iot.device.mapper.DeviceMapper;
import com.iot.device.model.DeviceStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class DeviceService {
    @Autowired
    private DeviceMapper deviceMapper;

    public List<DeviceStatus> getDeviceStatus(String orderField) {
        String safeField = sanitizeInput(orderField);
        return deviceMapper.queryDeviceStatus(safeField);
    }

    private String sanitizeInput(String input) {
        if (input == null || input.trim().isEmpty()) {
            return "default_field";
        }
        // 错误的转义逻辑：仅处理单引号
        return input.replace("'"， "''");
    }
}

package com.iot.device.mapper;

import com.iot.device.model.DeviceStatus;
import org.apache.ibatis.annotations.Mapper;
import java.util.List;

@Mapper
public interface DeviceMapper {
    List<DeviceStatus> queryDeviceStatus(String orderField);
}

// MyBatis XML映射文件：DeviceMapper.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.iot.device.mapper.DeviceMapper">
    <select id="queryDeviceStatus" resultType="com.iot.device.model.DeviceStatus">
        SELECT * FROM device_status
        ORDER BY ${orderField}  <!-- 漏洞点：使用${}导致SQL注入 -->
    </select>
</mapper>

// 设备状态模型
package com.iot.device.model;

public class DeviceStatus {
    private String deviceId;
    private int status;
    private long timestamp;
    // getter/setter
}

// 安全配置类（迷惑性代码）
package com.iot.device.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/v1/devices/**").authenticated()
            .and()
            .httpBasic();
    }
}