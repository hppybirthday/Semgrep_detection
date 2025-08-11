package com.example.mathsim.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/experiments")
public class ExperimentController {
    @Autowired
    private ExperimentService experimentService;

    @GetMapping
    public List<Experiment> getExperiments(@RequestParam String sort, @RequestParam String order) {
        return experimentService.getSortedExperiments(sort, order);
    }
}

package com.example.mathsim.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class ExperimentService {
    @Autowired
    private ExperimentMapper experimentMapper;

    public List<Experiment> getSortedExperiments(String sort, String order) {
        return experimentMapper.findSortedExperiments(sort, order);
    }
}

package com.example.mathsim.mapper;

import com.example.mathsim.model.Experiment;
import org.apache.ibatis.annotations.Mapper;
import java.util.List;

@Mapper
public interface ExperimentMapper {
    List<Experiment> findSortedExperiments(@Param("sort") String sort, @Param("order") String order);
}

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mathsim.mapper.ExperimentMapper">
  <select id="findSortedExperiments" resultType="com.example.mathsim.model.Experiment">
    SELECT * FROM experiments
    ORDER BY ${sort} ${order}
  </select>
</mapper>

package com.example.mathsim.model;

public class Experiment {
    private Long id;
    private String name;
    private Double result;
    // Getters and setters
}
