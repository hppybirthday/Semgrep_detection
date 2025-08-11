package com.example.mathsim;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/simulate")
public class SimulationServlet extends HttpServlet {
    private ModelService modelService = new ModelService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) 
        throws ServletException, IOException {
        
        String modelName = req.getParameter("modelName");
        String param = req.getParameter("param");
        
        // 创建并保存模型
        MathModel model = new MathModel();
        model.setName(modelName);
        model.setParameter(param);
        modelService.saveModel(model);
        
        // 展示模型
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><body>");
        out.println("<h2>Simulation Results for: " + model.getName() + "</h2>");
        out.println("<p>Parameter Value: " + model.getParameter() + "</p>");
        out.println("</body></html>");
    }
}

class MathModel {
    private String name;
    private String parameter;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getParameter() { return parameter; }
    public void setParameter(String parameter) { this.parameter = parameter; }
}

class ModelService {
    public void saveModel(MathModel model) {
        // 模拟持久化存储
        System.out.println("Saving model: " + model.getName());
    }
}