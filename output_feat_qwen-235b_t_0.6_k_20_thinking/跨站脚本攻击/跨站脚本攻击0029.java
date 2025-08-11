package com.example.mathsim;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.templateresolver.ServletContextTemplateResolver;

@WebServlet("/model/*")
public class ModelSimulationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private TemplateEngine templateEngine;
    private ModelService modelService = new ModelService();

    @Override
    public void init() {
        ServletContextTemplateResolver resolver = new ServletContextTemplateResolver(getServletContext());
        resolver.setPrefix("/WEB-INF/templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode("HTML5");
        templateEngine = new TemplateEngine();
        templateEngine.setTemplateResolver(resolver);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String modelId = request.getPathInfo().substring(1);
        WebContext context = new WebContext(request, response, getServletContext());
        context.setVariable("parameters", modelService.getParameters(modelId));
        context.setVariable("modelId", modelId);
        templateEngine.process("model-details", context, response.getWriter());
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String modelId = request.getPathInfo().substring(1);
        String paramName = request.getParameter("paramName");
        String paramValue = request.getParameter("paramValue");
        
        modelService.addParameter(modelId, new ModelParameter(paramName, paramValue));
        response.sendRedirect(request.getRequestURL().toString());
    }
}

class ModelService {
    private List<ModelParameter> parameters = new ArrayList<>();

    public List<ModelParameter> getParameters(String modelId) {
        return parameters;
    }

    public void addParameter(String modelId, ModelParameter parameter) {
        parameters.add(parameter);
    }
}

class ModelParameter {
    private String name;
    private String value;

    public ModelParameter(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() { return name; }
    public String getValue() { return value; }
}

// model-details.html
// <html>
// <body>
//   <h1>Model: <span th:text="${modelId}"></span></h1>
//   <div th:each="param : ${parameters}">
//     <strong th:text="${param.name}"></strong>: 
//     <span th:text="${param.value}"></span>
//   </div>
//   <form method="POST">
//     <input type="text" name="paramName" placeholder="Parameter name">
//     <input type="text" name="paramValue" placeholder="Value">
//     <button type="submit">Add</button>
//   </form>
// </body>
// </html>