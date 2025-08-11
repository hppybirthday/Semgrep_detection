package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/models")
public class ModelController {
    @Autowired
    private ModelService modelService;

    @GetMapping("/search")
    public List<ModelResult> searchModels(String queryText) {
        return modelService.searchModels(queryText);
    }
}

@Service
class ModelService {
    @Autowired
    private ModelMapper modelMapper;

    public List<ModelResult> searchModels(String queryText) {
        return modelMapper.searchModels(queryText);
    }
}

@Mapper
interface ModelMapper {
    @Select("SELECT * FROM model_results WHERE result_name LIKE '%${queryText}%' ")
    List<ModelResult> searchModels(String queryText);
}

@Data
class ModelResult {
    private Long id;
    private String resultName;
    private String modelName;
    private Double accuracy;
}

// 漏洞特征：
// 1. Controller层直接接收queryText参数
// 2. Mapper层使用${queryText}进行动态SQL拼接
// 3. 未对输入进行任何过滤或参数化处理
// 攻击示例：queryText=' OR '1'='1' UNION SELECT * FROM users--