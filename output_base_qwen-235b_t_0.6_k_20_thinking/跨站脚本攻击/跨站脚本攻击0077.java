package com.mathsim.core.model;

import java.util.HashMap;
import java.util.Map;

public class MathematicalModel {
    private String modelName;
    private Map<String, String> parameters;

    public MathematicalModel(String modelName) {
        this.modelName = modelName;
        this.parameters = new HashMap<>();
    }

    public void addParameter(String key, String value) {
        parameters.put(key, value);
    }

    public String getModelName() {
        return modelName;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }
}

package com.mathsim.core.service;

import com.mathsim.core.model.MathematicalModel;
import javax.servlet.http.HttpSession;

public class ModelService {
    public void saveModel(HttpSession session, MathematicalModel model) {
        session.setAttribute("currentModel", model);
    }

    public MathematicalModel createModel(String modelName) {
        return new MathematicalModel(modelName);
    }
}

package com.mathsim.web.controller;

import com.mathsim.core.model.MathematicalModel;
import com.mathsim.core.service.ModelService;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.PrintWriter;

public class ModelController extends HttpServlet {
    private ModelService modelService = new ModelService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        String modelName = req.getParameter("modelName");
        String paramKey = req.getParameter("paramKey");
        String paramValue = req.getParameter("paramValue");

        MathematicalModel model = modelService.createModel(modelName);
        model.addParameter(paramKey, paramValue);
        modelService.saveModel(req.getSession(), model);

        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><body>");
        out.println("<h2>Model Created: " + modelName + "</h2>");
        out.println("<p>Parameter: " + paramKey + " = " + paramValue + "</p>");
        out.println("<a href=\\"/MathSim/display\\">View Model</a>");
        out.println("</body></html>");
    }
}

package com.mathsim.web.display;

import com.mathsim.core.model.MathematicalModel;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.PrintWriter;

public class ModelDisplay extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        MathematicalModel model = (MathematicalModel) req.getSession().getAttribute("currentModel");
        
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><body>");
        out.println("<h1>Model: " + model.getModelName() + "</h1>");
        out.println("<ul>");
        model.getParameters().forEach((k, v) -> 
            out.println("<li>" + k + " = " + v + "</li>")
        );
        out.println("</ul>");
        out.println("</body></html>");
    }
}