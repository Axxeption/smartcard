package be.msec;
import be.msec.helpers.Controller;
import javafx.application.Platform;
import javafx.fxml.FXML;

public class RootMenuController extends Controller {

    private Main main;

    public void setMain(Main main) {
        this.main = main;
    }

    @FXML
    public void exitApplication() {
        Platform.exit();
    }

}
