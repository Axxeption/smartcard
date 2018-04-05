package be.msec.controllers;
import be.msec.ServiceProviderMain;
import be.msec.helpers.Controller;
import javafx.application.Platform;
import javafx.fxml.FXML;

public class RootMenuController extends Controller {

    private ServiceProviderMain serviceProviderMain;

    public void setMain(ServiceProviderMain serviceProviderMain) {
        this.serviceProviderMain = serviceProviderMain;
    }

    @FXML
    public void exitApplication() {
        Platform.exit();
    }

}
