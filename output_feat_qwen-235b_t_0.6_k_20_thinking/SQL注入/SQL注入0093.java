package com.example.mathmodelling;

import org.apache.ibatis.jdbc.SQL;
import java.util.List;

// Model类
public class SimulationModel {
    private int id;
    private String modelName;
    private double parameterA;
    private double parameterB;
    
    // Getters and Setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getModelName() { return modelName; }
    public void setModelName(String modelName) { this.modelName = modelName; }
    public double getParameterA() { return parameterA; }
    public void setParameterA(double parameterA) { this.parameterA = parameterA; }
    public double getParameterB() { return parameterB; }
    public void setParameterB(double parameterB) { this.parameterB = parameterB; }
}

// Mapper接口
interface SimulationMapper {
    List<SimulationModel> selectByExample(String sort, String order);
}

// XML映射器（实际应放在XML文件中，此处为演示合并到代码）
// <select id="selectByExample" resultType="SimulationModel">
//   SELECT * FROM simulation_models
//   ORDER BY ${sort} ${order}
// </select>

// Service层
class SimulationService {
    private SimulationMapper mapper;

    public SimulationService(SimulationMapper mapper) {
        this.mapper = mapper;
    }

    public List<SimulationModel> getSortedModels(String sort, String order) {
        // 漏洞点：直接传递用户输入参数到SQL拼接
        return mapper.selectByExample(sort, order);
    }
}

// Controller层
public class SimulationController {
    private SimulationService service;

    public SimulationController(SimulationService service) {
        this.service = service;
    }

    // 模拟接口调用
    public void handleRequest(String sortParam, String orderParam) {
        List<SimulationModel> models = service.getSortedModels(sortParam, orderParam);
        // 实际应返回models给前端
        System.out.println("模型数量：" + models.size());
    }

    public static void main(String[] args) {
        // 模拟正常请求
        SimulationController controller = new SimulationController(new SimulationService(/* MockMapper */));
        // 正常参数示例：
        // controller.handleRequest("parameterA", "ASC");
        // 恶意参数示例：
        controller.handleRequest("1; DROP TABLE simulation_models;--", "ASC");
    }
}