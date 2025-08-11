package com.example.mathsim;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 数学模型展示控制器
 */
@WebServlet("/model/display")
public class ModelDisplayServlet extends HttpServlet {
    private Map<String, MathModel> modelStore = new HashMap<>();

    public ModelDisplayServlet() {
        // 初始化示例模型
        modelStore.put("lorenz", new MathModel("Lorenz Attractor", 
            "dx/dt = σ(y-x)\
dy/dt = x(ρ-z)-y\
dz/dt = xy-βz"));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        String modelName = request.getParameter("name");
        
        if (modelName == null || modelName.isEmpty()) {
            response.getWriter().write("<h1>No model specified</h1>");
            return;
        }

        MathModel model = modelStore.getOrDefault(modelName, 
            new MathModel("Unknown Model", "Model not found"));
            
        // 存在XSS漏洞的代码：直接将用户输入拼接到HTML中
        String html = "<html><head><title>" + model.getName() + "</title></head>"
                   + "<body><h1>" + model.getName() + "</h1>"
                   + "<pre>" + model.getEquations() + "</pre>"
                   + "<div>Parameters: " + request.getParameter("params") + "</div>"
                   + "</body></html>";
                   
        response.getWriter().write(html);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String name = request.getParameter("name");
        String equations = request.getParameter("equations");
        
        if (name != null && equations != null) {
            modelStore.put(name.toLowerCase(), new MathModel(name, equations));
            response.sendRedirect("/model/display?name=" + name);
        }
    }
}

class MathModel {
    private String name;
    private String equations;

    public MathModel(String name, String equations) {
        this.name = name;
        this.equations = equations;
    }

    public String getName() {
        return name;
    }

    public String getEquations() {
        return equations;
    }
}