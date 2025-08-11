import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.alibaba.fastjson.JSON;

@WebServlet("/depot/*")
public class SimulationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String path = request.getPathInfo();
        if (path == null || path.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        try {
            if (path.equals("/add")) {
                GeometryModel model = FastJsonConvert.convertJSONToObject(request.getInputStream(), GeometryModel.class);
                processGeometry(model);
                response.getWriter().println("Model added successfully");
            } 
            else if (path.equals("/update")) {
                PhysicsModel[] models = FastJsonConvert.convertJSONToArray(request.getInputStream(), PhysicsModel[].class);
                updatePhysicsParameters(models);
                response.getWriter().println("Models updated successfully");
            }
            else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private void processGeometry(GeometryModel model) {
        System.out.println("Processing geometry: " + model.getType() + " with volume: " + model.calculateVolume());
    }

    private void updatePhysicsParameters(PhysicsModel[] models) {
        for (PhysicsModel model : models) {
            System.out.println("Updating physics model: " + model.getName() + " with force: " + model.getForce());
        }
    }
}

class GeometryModel {
    private String type;
    private double length, width, height;

    public String getType() { return type; }
    public double calculateVolume() { return length * width * height; }
}

class PhysicsModel {
    private String name;
    private double force;

    public String getName() { return name; }
    public double getForce() { return force; }
}

class FastJsonConvert {
    public static <T> T convertJSONToObject(InputStream is, Class<T> clazz) {
        return JSON.parseObject(is, clazz); // 不安全的反序列化调用
    }

    public static <T> T convertJSONToArray(InputStream is, Class<T> clazz) {
        return JSON.parseArray(is, clazz); // 不安全的数组反序列化调用
    }
}