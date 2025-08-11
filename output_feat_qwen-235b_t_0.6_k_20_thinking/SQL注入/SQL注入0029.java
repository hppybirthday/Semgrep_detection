package com.example.demo.simulation;

import com.baomidou.mybatisplus.annotation.*;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/simulation")
public class SimulationController {
    @Autowired
    private SimulationService simulationService;

    @GetMapping("/data")
    public List<SimulatedData> getSimulatedData(@RequestParam String orderBy) {
        return simulationService.getSortedData(orderBy);
    }
}

@Service
class SimulationService extends ServiceImpl<SimulationMapper, SimulatedData> {
    public List<SimulatedData> getSortedData(String orderBy) {
        return query().select(SimulatedData.class, wrapper -> wrapper.select(SimulatedData::getId, SimulatedData::getValue, SimulatedData::getType)
            .orderBy(true, true, orderBy)).list();
    }
}

interface SimulationMapper extends BaseMapper<SimulatedData> {
    @Select({"<script>",
        "SELECT id, value, type FROM simulated_data ORDER BY ${orderBy}",
        "</script>"})
    List<SimulatedData> selectOrderedData(@Param("orderBy") String orderBy);
}

@TableName("simulated_data")
class SimulatedData {
    @TableId(value = "id", type = IdType.AUTO)
    private Long id;
    private Double value;
    private String type;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Double getValue() { return value; }
    public void setValue(Double value) { this.value = value; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
}