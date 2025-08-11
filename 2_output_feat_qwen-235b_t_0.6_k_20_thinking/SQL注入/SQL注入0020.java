package com.example.iot.device.controller;

import com.example.iot.device.service.DeviceService;
import com.example.iot.common.PageResult;
import com.example.iot.device.model.DeviceQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

/**
 * IoT设备管理控制器
 */
@RestController
@RequestMapping("/api/v1/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    /**
     * 分页查询设备信息
     * @param pageNum 页码
     * @param pageSize 页大小
     * @param status 设备状态
     * @param sort 排序字段
     * @param order 排序方式
     * @return 分页结果
     */
    @GetMapping("/list")
    public PageResult<List<DeviceQuery>> listDevices(@RequestParam int pageNum,
                                                      @RequestParam int pageSize,
                                                      @RequestParam(required = false) String status,
                                                      @RequestParam(required = false) String sort,
                                                      @RequestParam(required = false) String order) {
        // 构造排序参数
        String orderBy = "";
        if (sort != null && order != null) {
            orderBy = " ORDER BY " + sort + " " + order;
        }
        
        // 构造查询条件
        StringBuilder condition = new StringBuilder();
        if (status != null) {
            condition.append(" AND status='").append(status).append("'");
        }
        
        // 调用服务层处理分页查询
        return deviceService.getDevicesByPage(pageNum, pageSize, condition.toString(), orderBy);
    }
}

// DeviceService.java
package com.example.iot.device.service;

import com.example.iot.common.PageResult;
import com.example.iot.device.model.DeviceQuery;
import com.example.iot.device.mapper.DeviceMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DeviceService {
    @Autowired
    private DeviceMapper deviceMapper;

    public PageResult<List<DeviceQuery>> getDevicesByPage(int pageNum, int pageSize, String condition, String orderBy) {
        // 构造分页SQL
        int offset = (pageNum - 1) * pageSize;
        String querySql = "SELECT * FROM devices WHERE 1=1" + condition + orderBy + " LIMIT " + offset + "," + pageSize;
        String countSql = "SELECT COUNT(*) FROM devices WHERE 1=1" + condition;
        
        // 执行查询
        List<DeviceQuery> devices = deviceMapper.selectDevices(querySql);
        int total = deviceMapper.countDevices(countSql);
        
        return new PageResult<>(devices, total, pageNum, pageSize);
    }
}

// DeviceMapper.java
package com.example.iot.device.mapper;

import com.example.iot.device.model.DeviceQuery;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DeviceMapper {
    @Select("${querySql}")
    List<DeviceQuery> selectDevices(@Param("querySql") String querySql);
    
    @Select("${countSql}")
    int countDevices(@Param("countSql") String countSql);
}