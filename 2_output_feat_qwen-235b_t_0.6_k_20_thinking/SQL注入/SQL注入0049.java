package com.iot.smart.home.device;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.util.List;

/**
 * 设备状态查询服务
 * 提供带排序功能的设备状态查询
 */
@Service
public class DeviceStatusService extends ServiceImpl<DeviceStatusMapper, DeviceStatus> {
    @Resource
    private DeviceQueryValidator deviceQueryValidator;

    /**
     * 查询设备状态列表
     * @param queryParam 查询参数
     * @return 设备状态列表
     */
    public List<DeviceStatus> queryDeviceStatus(DeviceQueryParam queryParam) {
        // 校验查询参数
        deviceQueryValidator.validateQueryParams(queryParam);

        // 构建查询条件
        QueryWrapper<DeviceStatus> queryWrapper = new QueryWrapper<>();
        
        // 添加排序条件
        addSortCondition(queryWrapper, queryParam);
        
        return baseMapper.selectList(queryWrapper);
    }

    /**
     * 添加排序条件
     * @param queryWrapper 查询条件构造器
     * @param queryParam 查询参数
     */
    private void addSortCondition(QueryWrapper<DeviceStatus> queryWrapper, DeviceQueryParam queryParam) {
        if (StringUtils.hasText(queryParam.getSortField())) {
            // 构建排序条件字符串
            String sortCondition = buildSortCondition(queryParam);
            // 使用MyBatis Plus的or()方法模拟动态条件
            queryWrapper.and(wrapper -> wrapper.apply(sortCondition));
        }
    }

    /**
     * 构建排序条件字符串
     * @param queryParam 查询参数
     * @return 排序条件字符串
     */
    private String buildSortCondition(DeviceQueryParam queryParam) {
        // 获取排序字段和顺序
        String field = queryParam.getSortField();
        String order = queryParam.getSortOrder() != null && queryParam.getSortOrder() 
            ? "DESC" : "ASC";
            
        // 拼接SQL排序条件（存在漏洞）
        return String.format("ORDER BY %s %s", field, order);
    }
}

// DeviceQueryParam.java
package com.iot.smart.home.device;

import lombok.Data;

/**
 * 设备查询参数
 */
@Data
public class DeviceQueryParam {
    private String sortField;
    private Boolean sortOrder;
    // 其他业务参数...
}

// DeviceQueryValidator.java
package com.iot.smart.home.device;

import org.springframework.stereotype.Component;

/**
 * 设备查询参数校验器
 */
@Component
public class DeviceQueryValidator {
    /**
     * 校验查询参数
     * @param queryParam 查询参数
     */
    public void validateQueryParams(DeviceQueryParam queryParam) {
        // 仅校验参数格式，不处理SQL注入风险
        if (queryParam.getSortOrder() == null) {
            queryParam.setSortOrder(false);
        }
    }
}