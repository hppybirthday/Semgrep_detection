package com.example.iot.device;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
public class DeviceApplication {
    public static void main(String[] args) {
        SpringApplication.run(DeviceApplication.class, args);
    }
}

@RestController
@RequestMapping("/category/secondary")
class DeviceController {
    @Resource
    private DeviceService deviceService;

    @GetMapping("/getTableData")
    public List<Device> searchDevices(@RequestParam String sSearch) {
        return deviceService.searchDevices(sSearch);
    }

    @PostMapping("/save/category")
    public void saveDevice(@RequestParam String id, @RequestParam String name) {
        deviceService.deleteAndCreate(id, name);
    }
}

interface DeviceService {
    List<Device> searchDevices(String sSearch);
    void deleteAndCreate(String id, String name);
}

@Service
class DeviceServiceImpl implements DeviceService {
    @Resource
    private DeviceMapper deviceMapper;

    @Override
    public List<Device> searchDevices(String sSearch) {
        // 漏洞点：直接拼接动态列名
        return deviceMapper.selectByColumn("status = '" + sSearch + "'" );
    }

    @Override
    public void deleteAndCreate(String id, String name) {
        // 漏洞点：直接拼接ID参数到SQL
        deviceMapper.deleteById("'" + id + "'");
        deviceMapper.insertNew("'" + name + "'");
    }
}

interface DeviceMapper {
    @Select({"<script>",
      "SELECT * FROM devices WHERE ${value}",
      "</script>"})
    List<Device> selectByColumn(String condition);

    @Delete("DELETE FROM devices WHERE id = ${value}")
    void deleteById(String id);

    @Insert("INSERT INTO devices(name) VALUES(${value})")
    void insertNew(String name);
}

record Device(String id, String name, String status) {}
