package com.example.crm.controller;

import com.example.crm.service.GoodsService;
import com.example.crm.model.Goods;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/goods")
public class GoodsController {
    @Autowired
    private GoodsService goodsService;

    @GetMapping("/list")
    public List<Goods> getGoodsList(@RequestParam String ids) {
        return goodsService.getGoodsByIds(ids);
    }
}

package com.example.crm.service;

import com.example.crm.mapper.GoodsMapper;
import com.example.crm.model.Goods;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GoodsService {
    @Autowired
    private GoodsMapper goodsMapper;

    public List<Goods> getGoodsByIds(String ids) {
        return goodsMapper.selectByIds(ids);
    }
}

package com.example.crm.mapper;

import com.example.crm.model.Goods;
import org.beetl.sql.core.mapper.BaseMapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GoodsMapper extends BaseMapper<Goods> {
    List<Goods> selectByIds(@Param("ids") String ids);
}

package com.example.crm.model;

public class Goods {
    private Integer id;
    private String name;
    private Double price;
    // getters and setters
}

// Mapper XML (BeetlSQL配置文件中)
/*
<sql id="selectByIds">
    SELECT * FROM goods WHERE id IN (${ids})
</sql>
*/