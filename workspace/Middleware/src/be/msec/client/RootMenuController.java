package be.msec.client;
import javafx.application.Platform;
import javafx.fxml.FXML;

public class RootMenuController {

    private MiddlewareMain main;

    public void setMain(MiddlewareMain main) {
        this.main = main;
    }

    @FXML
    public void exitApplication() {
        Platform.exit();
    }

}
