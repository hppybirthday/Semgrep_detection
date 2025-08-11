import java.io.*;
public class DataCleaner {
    public static void main(String[] args) throws Exception {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Input source: ");
        String src = r.readLine();
        System.out.print("Filter pattern: ");
        String pattern = r.readLine();
        Process p = Runtime.getRuntime().exec(
            new String[]{"/bin/sh", "-c", "cat " + src + " | grep -i '" + pattern + "' > filtered.txt"}
        );
        p.waitFor();
        System.out.println("Processing complete");
    }
}
// Compile: javac DataCleaner.java
// Run: java DataCleaner