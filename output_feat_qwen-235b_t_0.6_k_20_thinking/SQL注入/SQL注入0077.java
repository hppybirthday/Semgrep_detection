package com.example.mathmodelling;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.util.List;

// 领域模型
class Simulation {
    private Long id;
    private String modelName;
    private String parameters;
    // 省略getter/setter
}

// Mapper接口
interface SimulationMapper {
    List<Simulation> queryByCondition(Example example);
}

// Service层
@Service
class SimulationService {
    @Autowired
    private SimulationMapper simulationMapper;

    public List<Simulation> getCriticalSimulations(String orderField) {
        Example example = new Example(Simulation.class);
        // 漏洞点：直接拼接orderField参数到SQL语句
        example.setOrderByClause(String.format("%s DESC", orderField));
        
        // 模拟业务逻辑：查询参数包含敏感数据模型
        Example.Criteria criteria = example.createCriteria();
        criteria.andLike("parameters", "%sensitive%");
        
        return simulationMapper.queryByCondition(example);
    }
}

// Controller层
@RestController
@RequestMapping("/api/simulations")
class SimulationController {
    @Autowired
    private SimulationService simulationService;

    @GetMapping("/critical")
    public List<Simulation> listCriticalSimulations(
        @RequestParam(name = "sort_by", defaultValue = "id") String orderField
    ) {
        return simulationService.getCriticalSimulations(orderField);
    }
}

// MyBatis Example类（简化版）
class Example {
    private String orderByClause;
    private List<Criteria> oredCriteria;
    
    // 简化实现
    public void setOrderByClause(String clause) {
        this.orderByClause = clause;
    }
    
    public Criteria createCriteria() {
        Criteria criteria = new Criteria();
        oredCriteria.add(criteria);
        return criteria;
    }
}

class Criteria {
    public Criteria andLike(String field, String value) {
        // 实际实现会构造SQL条件
        return this;
    }
}