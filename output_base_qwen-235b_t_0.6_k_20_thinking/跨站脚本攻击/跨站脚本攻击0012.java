import static spark.Spark.*;
import java.util.*;
import java.util.concurrent.*;

public class CrmXss {
    static Map<String, String> customers = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        port(8080);

        get("/add", (req, res) -> "<form method='post'>Name: <input name='name'>\
" +
            "Note: <input name='note'><input type='submit'></form>");

        post("/add", (req, res) -> {
            String name = req.queryParams("name");
            String note = req.queryParams("note");
            customers.put(name, note);
            res.redirect("/list");
            return null;
        });

        get("/list", (req, res) -> {
            StringBuilder html = new StringBuilder("<h1>Customers</h1><ul>");
            customers.forEach((name, note) -> html.append(String.format(
                "<li><b>%s</b>: %s</li>", name, note
            )));
            return html.append("</ul>").toString();
        });

        get("/search", (req, res) -> {
            String query = req.queryParams("q");
            return String.format("<input type='text' value='%s'>\
" +
                "<p>Search results for: %s</p>", query, query);
        });
    }
}