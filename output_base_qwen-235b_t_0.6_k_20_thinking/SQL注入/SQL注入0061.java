package com.example.mathsim;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.List;

@Stateless
public class SimulationService {
    @PersistenceContext
    private EntityManager em;

    // 模拟数学模型实体
    public static class SimulationModel {
        private String modelName;
        private String parameters;
        // 构造方法/getter/setter省略
        
        public SimulationModel(String modelName, String parameters) {
            this.modelName = modelName;
            this.parameters = parameters;
        }
    }

    // 存在漏洞的模型查询方法
    public List<?> runSimulationQuery(String modelName, String paramFilter) {
        String queryString = String.format(
            "SELECT m FROM SimulationModel m WHERE m.modelName = '%s' AND m.parameters LIKE '%%%s%%'",
            modelName, paramFilter);
        Query query = em.createQuery(queryString);
        return query.getResultList();
    }

    // 模拟攻击场景
    public void simulateAttack() {
        // 正常调用
        System.out.println("正常查询：");
        runSimulationQuery("lorenz_attractor", "chaos=true");
        
        // 注入攻击
        System.out.println("\
SQL注入攻击：");
        String maliciousModelName = "1'; DROP TABLE simulation_models;--";
        String maliciousParam = "1' OR '1'='1";
        runSimulationQuery(maliciousModelName, maliciousParam);
    }

    // 模型持久化方法
    public void saveModel(String modelName, String parameters) {
        em.persist(new SimulationModel(modelName, parameters));
    }

    // 初始化测试数据
    public void initTestData() {
        saveModel("lorenz_attractor", "sigma=10,rho=28,beta=8/3");
        saveModel("rossler_attractor", "a=0.2,b=0.2,c=5.7");
    }

    // 主方法模拟运行
    public static void main(String[] args) {
        SimulationService service = new SimulationService();
        service.initTestData();
        service.simulateAttack();
    }
}