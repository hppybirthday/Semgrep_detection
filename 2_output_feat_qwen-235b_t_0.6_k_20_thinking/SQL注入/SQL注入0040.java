package com.example.mathmod.controller;

import com.example.mathmod.service.ModelRunService;
import com.example.mathmod.dto.QueryDTO;
import com.example.mathmod.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/model/run")
public class ModelRunController {
    @Autowired
    private ModelRunService modelRunService;

    @GetMapping("/results")
    public Result<List<ModelRunResult>> queryResults(QueryDTO queryDTO) {
        // 构建查询条件
        if (queryDTO.getParams() == null) {
            queryDTO.setParams("{}");
        }
        
        List<ModelRunResult> results = modelRunService.search(queryDTO);
        return Result.success(results);
    }
}

// -------------------------------------

package com.example.mathmod.service;

import com.example.mathmod.dao.ModelRunDAO;
import com.example.mathmod.dto.QueryDTO;
import com.example.mathmod.entity.ModelRunResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ModelRunService {
    @Autowired
    private ModelRunDAO modelRunDAO;

    public List<ModelRunResult> search(QueryDTO queryDTO) {
        // 处理业务逻辑
        String filter = processFilter(queryDTO);
        return modelRunDAO.queryResults(filter);
    }

    private String processFilter(QueryDTO queryDTO) {
        // 构建动态查询条件
        StringBuilder condition = new StringBuilder();
        if (queryDTO.getRunId() != null && !queryDTO.getRunId().isEmpty()) {
            condition.append(" AND run_id IN (").append(queryDTO.getRunId()).append(")");
        }
        if (queryDTO.getModelType() != null && !queryDTO.getModelType().isEmpty()) {
            condition.append(" AND model_type = '").append(queryDTO.getModelType()).append("'");
        }
        return condition.toString();
    }
}

// -------------------------------------

package com.example.mathmod.dao;

import com.example.mathmod.entity.ModelRunResult;
import org.beetl.sql.core.mapper.BaseMapper;
import org.beetl.sql.core.SQLReady;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ModelRunDAO extends BaseMapper<ModelRunResult> {
    default List<ModelRunResult> queryResults(String filterCondition) {
        // 构建动态SQL查询
        String sql = new SQLReady("SELECT * FROM model_run_results WHERE 1=1" + filterCondition).getText();
        return this.execute(sql, ModelRunResult.class);
    }
}