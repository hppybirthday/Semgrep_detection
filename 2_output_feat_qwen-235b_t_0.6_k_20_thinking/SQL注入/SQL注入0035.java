package com.example.ml.model;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import javax.annotation.Resource;
import java.util.List;

/**
 * 模型管理数据访问层
 */
@Mapper
public interface ModelMapper {
    @Delete({"<script>",
      "DELETE FROM model_table WHERE model_name IN ",
      "<foreach item='name' collection='names' open='(' separator=',' close=')'>",
      "#{name}",
      "</foreach>",
      "</script>"})
    int deleteModels(List<String> names);
}

package com.example.ml.model;

import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 模型管理服务类
 */
@Service
public class ModelService {
    @Resource
    private ModelMapper modelMapper;

    /**
     * 删除指定名称的模型
     * @param names 模型名称列表
     * @return 删除数量
     */
    public int deleteModels(List<String> names) {
        if (names == null || names.isEmpty()) {
            return 0;
        }
        // 过滤空字符串
        List<String> validNames = names.stream()
                .filter(name -> name != null && !name.trim().isEmpty())
                .toList();
        
        return modelMapper.deleteModels(validNames);
    }
}

package com.example.ml.model;

import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

/**
 * 模型管理控制器
 */
@RestController
@RequestMapping("/api/model")
public class ModelController {
    @Resource
    private ModelService modelService;

    /**
     * 批量删除模型
     * @param names 模型名称列表
     * @return 删除数量
     */
    @DeleteMapping("/delete")
    public int batchDelete(@RequestParam("names") List<String> names) {
        return modelService.deleteModels(names);
    }
}