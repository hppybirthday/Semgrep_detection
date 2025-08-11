package com.example.mathmodelling.dao;

import com.example.mathmodelling.model.Simulation;
import com.example.mathmodelling.model.SimulationExample;
import org.apache.ibatis.jdbc.SQL;

import java.util.List;

public class SimulationDao {
    public List<Simulation> listSimulations(String username, String mobile, String sort, String order) {
        SimulationExample example = new SimulationExample();
        if (username != null && !username.isEmpty()) {
            example.createCriteria().andUsernameEqualTo(username);
        }
        if (mobile != null && !mobile.isEmpty()) {
            example.createCriteria().andMobileEqualTo(mobile);
        }
        
        // SQL注入漏洞点：动态拼接ORDER BY
        String orderByClause = "";
        if (sort != null && order != null) {
            orderByClause = sort + " " + order;
        }
        example.setOrderByClause(orderByClause);
        
        return sqlSession.selectList("listSimulations", example);
    }
}

// MyBatis Mapper XML
/*
<select id="listSimulations" parameterType="com.example.mathmodelling.model.SimulationExample" resultType="com.example.mathmodelling.model.Simulation">
    SELECT * FROM simulations
    <where>
        <if test="criteria.username != null">
            AND username = #{criteria.username}
        </if>
        <if test="criteria.mobile != null">
            AND mobile = #{criteria.mobile}
        </if>
    </where>
    <if test="orderByClause != null and orderByClause != ''">
        ORDER BY ${orderByClause} <!-- 使用${}导致SQL注入 -->
    </if>
</select>
*/

// Controller层示例
@RequestMapping("/list")
public List<Simulation> getSimulations(@RequestParam String username, 
                                       @RequestParam String mobile,
                                       @RequestParam String sort,
                                       @RequestParam String order) {
    // 未对输入参数做任何验证
    return simulationDao.listSimulations(username, mobile, sort, order);
}

// Service层直接传递参数到DAO
public class SimulationService {
    public List<Simulation> getSimulationList(String username, String mobile, String sort, String order) {
        return simulationDao.listSimulations(username, mobile, sort, order);
    }
}