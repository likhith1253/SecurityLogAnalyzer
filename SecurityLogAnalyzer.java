import com.sla.app.MainController;
import com.sla.util.AnsiColors;

/**
 * Security Log Analyzer (SLA) - v12.0 (Modular & Professional)
 * A forensic log analysis tool that uses Red-Black Tree data structure
 * for efficient log processing and threat detection.
 * 
 * @version 12.0
 */
public class SecurityLogAnalyzer {
    
    public static void main(String[] args) {
        System.out.println(AnsiColors.GRAY + "--> Working directory: " + 
            System.getProperty("user.dir") + AnsiColors.RESET);
        
        MainController controller = new MainController();
        controller.run();
    }
}
