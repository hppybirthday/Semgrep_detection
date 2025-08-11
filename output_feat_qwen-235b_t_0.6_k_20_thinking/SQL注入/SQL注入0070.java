package com.example.iotdemo;

import org.apache.ibatis.annotations.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
@MapperScan("com.example.iotdemo")
public class SqlInjectionDemo {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemo.class, args);
    }
}

// 设备实体类
class IoTDevice {
    private Long id;
    private String name;
    private String clientInfo;
    // 省略getter/setter
}

// Mapper接口
@Mapper
interface DeviceMapper {
    @Select("SELECT * FROM device WHERE id IN (${ids})")
    List<IoTDevice> selectByIds(@Param("ids") String ids);

    @Update({"<script>",
        "UPDATE device SET clientInfo = '${client}' WHERE id IN (${ids})",
        "</script>"})
    int updateClients(@Param("ids") String ids, @Param("client") String client);
}

// Service层
@Service
class DeviceService {
    @Resource
    DeviceMapper deviceMapper;

    public List<IoTDevice> getDevices(String deviceIds) {
        return deviceMapper.selectByIds(deviceIds);
    }

    public int updateDeviceClients(String deviceIds, String clientInfo) {
        // 漏洞点：直接拼接SQL IN子句和字符串值
        return deviceMapper.updateClients(deviceIds, clientInfo);
    }
}

// Controller层
@RestController
@RequestMapping("/api/devices")
class DeviceController {
    @Resource
    DeviceService deviceService;

    @PutMapping("/clients")
    public String updateClients(@RequestParam String ids, @RequestParam String client) {
        // 漏洞触发：直接传递原始输入到SQL层
        int count = deviceService.updateDeviceClients(ids, client);
        return count + " devices updated";
    }

    @GetMapping
    public List<IoTDevice> getDevices(@RequestParam String ids) {
        return deviceService.getDevices(ids);
    }
}

// 配置类（简化版）
@Configuration
class MyBatisConfig {
    // 实际项目中需要配置数据源和MyBatis-Plus相关配置
}