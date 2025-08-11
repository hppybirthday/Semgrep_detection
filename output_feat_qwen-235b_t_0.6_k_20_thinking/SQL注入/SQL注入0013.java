package com.example.mathsim.controller;

import com.example.mathsim.service.ExperimentService;
import com.example.mathsim.model.Experiment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/experiments")
public class ExperimentController {
    @Autowired
    private ExperimentService experimentService;

    @GetMapping
    public List<Experiment> getExperiments(@RequestParam String sort, @RequestParam String order) {
        return experimentService.findExperiments(sort, order);
    }
}

package com.example.mathsim.service;

import com.example.mathsim.dao.ExperimentDAO;
import com.example.mathsim.model.Experiment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ExperimentServiceImpl implements ExperimentService {
    @Autowired
    private ExperimentDAO experimentDAO;

    @Override
    public List<Experiment> findExperiments(String sort, String order) {
        return experimentDAO.queryExperiments(sort, order);
    }
}

package com.example.mathsim.dao;

import com.example.mathsim.model.Experiment;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ExperimentDAO {
    @Autowired
    private SQLManager sqlManager;

    public List<Experiment> queryExperiments(String sort, String order) {
        String sql = "SELECT * FROM experiments ORDER BY " + sort + " " + order;
        return sqlManager.createSqlQuery(sql).mapTo(Experiment.class).select();
    }
}

package com.example.mathsim.model;

import lombok.Data;

@Data
public class Experiment {
    private Long id;
    private String name;
    private String result;
}

// application.properties配置
// spring.datasource.url=jdbc:mysql://localhost:3306/math_sim
// spring.datasource.username=root
// spring.datasource.password=root
// beetlsql.basePackage=com.example.mathsim.dao