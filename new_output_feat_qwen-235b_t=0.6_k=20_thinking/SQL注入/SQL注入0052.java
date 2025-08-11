package com.iot.device.controller;

import com.iot.device.service.DeviceDataService;
import com.iot.device.dto.DeviceDataDTO;
import com.iot.device.common.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 设备数据采集管理Controller
 * 处理设备运行数据的查询与统计
 */
@RestController
@RequestMapping("/device/data")
public class DeviceDataController {
    @Autowired
    private DeviceDataService deviceDataService;

    /**
     * 分页查询设备采集数据
     * 支持动态排序与条件过滤
     */
    @GetMapping("/list")
    public PageResult<List<DeviceDataDTO>> list(
            @RequestParam(required = false) String deviceName,
            @RequestParam String sort,
            @RequestParam String order,
            @RequestParam int pageNum,
            @RequestParam int pageSize) {
        
        // 参数默认值处理
        sort = validateSortField(sort);
        order = validateSortOrder(order);
        
        return deviceDataService.getDeviceData(deviceName, sort, order, pageNum, pageSize);
    }

    /**
     * 验证排序字段合法性（白名单校验）
     */
    private String validateSortField(String field) {
        if (field == null || field.isEmpty()) {
            return "create_time";
        }
        // 允许字段：create_time,status,value
        if (!field.matches("(create_time|status|value)")) {
            throw new IllegalArgumentException("非法排序字段");
        }
        return field;
    }

    /**
     * 验证排序顺序合法性
     */
    private String validateSortOrder(String order) {
        if (order == null || order.isEmpty()) {
            return "desc";
        }
        if (!order.equalsIgnoreCase("asc") && !order.equalsIgnoreCase("desc")) {
            throw new IllegalArgumentException("非法排序顺序");
        }
        return order;
    }
}

package com.iot.device.service;

import com.iot.device.dao.DeviceDataDAO;
import com.iot.device.dto.DeviceDataDTO;
import com.iot.device.common.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 设备数据业务逻辑层
 * 实现数据过滤与分页处理
 */
@Service
public class DeviceDataServiceImpl implements DeviceDataService {
    @Autowired
    private DeviceDataDAO deviceDataDAO;

    @Override
    public PageResult<List<DeviceDataDTO>> getDeviceData(String deviceName, String sort, String order, int pageNum, int pageSize) {
        // 构造查询参数
        int offset = (pageNum - 1) * pageSize;
        
        // 构造动态SQL参数
        String orderByClause = String.format("%s %s", sort, order);
        
        // 执行数据查询
        List<DeviceDataDTO> dataList = deviceDataDAO.queryDeviceData(deviceName, orderByClause, offset, pageSize);
        int total = deviceDataDAO.countDeviceData(deviceName);
        
        return new PageResult<>(dataList, total, pageNum, pageSize);
    }
}

package com.iot.device.dao;

import com.iot.device.dto.DeviceDataDTO;
import org.beetl.sql.annotation.entity.SqlStatement;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 设备数据持久层
 * 使用BeetlSQL实现动态查询
 */
@Repository
public class DeviceDataDAO {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 查询设备数据（存在SQL注入漏洞）
     */
    @SqlStatement(params = "deviceName,orderByClause,offset,limit")
    public List<DeviceDataDTO> queryDeviceData(String deviceName, String orderByClause, int offset, int limit) {
        // language=SQL
        return sqlManager.execute(sql -> {
            sql.append("SELECT * FROM device_data WHERE 1=1");
            if (deviceName != null && !deviceName.isEmpty()) {
                sql.append(" AND device_name LIKE CONCAT('%%', ?, '%%')", deviceName);
            }
            if (orderByClause != null && !orderByClause.isEmpty()) {
                sql.append(" ORDER BY ").append(orderByClause);
            }
            sql.append(" LIMIT ?, ?", offset, limit);
            return sql.getList(DeviceDataDTO.class);
        });
    }

    /**
     * 统计设备数据量
     */
    @SqlStatement(params = "deviceName")
    public int countDeviceData(String deviceName) {
        return sqlManager.lambdaQuery(DeviceDataDTO.class)
                .andLike(DeviceDataDTO::getDeviceName, deviceName)
                .count();
    }
}