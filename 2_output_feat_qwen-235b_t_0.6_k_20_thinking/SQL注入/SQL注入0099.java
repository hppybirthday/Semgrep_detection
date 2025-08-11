package com.mathsim.model.controller;

import com.mathsim.model.service.MathModelParamService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 数学模型参数管理控制器
 * Created for simulation parameter management
 */
@RestController
@Tag(name = "MathModelParamController", description = "数学模型参数管理")
@RequestMapping("/model/param")
public class MathModelParamController {
    @Autowired
    private MathModelParamService mathModelParamService;

    @Operation(summary = "批量删除模型参数")
    @DeleteMapping("/delete")
    public boolean deleteModelParams(@RequestBody List<String> paramIds) {
        return mathModelParamService.deleteModelParams(paramIds.toArray(new String[0]));
    }
}

package com.mathsim.model.service;

import com.mathsim.model.dao.MathModelParamDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;

/**
 * 数学模型参数业务逻辑处理
 */
@Service
public class MathModelParamService {
    @Autowired
    private MathModelParamDao mathModelParamDao;

    /**
     * 删除模型参数（包含基础校验）
     * @param paramIds 参数ID数组
     * @return 操作结果
     */
    public boolean deleteModelParams(String[] paramIds) {
        if (paramIds == null || paramIds.length == 0) {
            return false;
        }
        
        // 转换为逗号分隔字符串并移除空格（业务规则）
        String idList = String.join(",", Arrays.stream(paramIds)
                            .map(id -> id.replaceAll("\\s+", ""))
                            .toArray(String[]::new));
        
        // 构造包含动态条件的删除语句
        String delCondition = String.format("id IN (%s) AND status=1", idList);
        return mathModelParamDao.delete(delCondition);
    }
}

package com.mathsim.model.dao;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

/**
 * 数学模型参数数据访问接口
 */
@Mapper
public interface MathModelParamDao {
    /**
     * 执行物理删除操作
     * @param condition 删除条件表达式
     * @return 影响记录数
     */
    @Delete({"<script>",
      "DELETE FROM simulation_params WHERE ${condition}",
      "</script>"})
    int delete(@Param("condition") String condition);
}