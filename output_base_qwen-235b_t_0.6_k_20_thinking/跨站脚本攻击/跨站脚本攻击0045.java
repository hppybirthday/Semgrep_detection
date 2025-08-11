import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import java.lang.reflect.*;

public class MathModelServlet extends HttpServlet {
    private Map<String, Model> models = new HashMap<>();

    @Override
    public void init() {
        models.put("linear", new LinearModel());
        models.put("exponential", new ExponentialModel());
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String modelInput = request.getParameter("model");
        String paramInput = request.getParameter("params");
        
        if (modelInput == null || paramInput == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing parameters");
            return;
        }
        
        try {
            Model model = models.get(modelInput.toLowerCase());
            if (model == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Model not found");
                return;
            }
            
            // Metaprogramming: Dynamic parameter handling
            Method method = model.getClass().getMethod("setParams", String.class);
            method.invoke(model, paramInput);
            
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            
            out.println("<html><body>");
            out.println("<h1>Model: " + model.getName() + "</h1>"); // Vulnerable line
            out.println("<div>Parameters: " + model.getParams() + "</div>");
            out.println("<div>Result: " + model.calculate() + "</div>");
            out.println("</body></html>");
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    interface Model {
        void setParams(String params);
        String getParams();
        String getName();
        double calculate();
    }

    static class LinearModel implements Model {
        private String params;
        private String name = "Linear Model";

        public void setParams(String params) { this.params = params; }
        public String getParams() { return params; }
        public String getName() { return name; }
        public double calculate() { 
            return Arrays.stream(params.split(",")).mapToDouble(Double::parseDouble).sum(); 
        }
    }

    static class ExponentialModel implements Model {
        private String params;
        private String name = "Exponential Model";

        public void setParams(String params) { this.params = params; }
        public String getParams() { return params; }
        public String getName() { return name; }
        public double calculate() { 
            return Arrays.stream(params.split(",")).mapToDouble(Double::parseDouble).reduce(1, (a,b) -> a * b); 
        }
    }
}