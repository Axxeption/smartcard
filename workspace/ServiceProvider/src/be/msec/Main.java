package be.msec;
import be.msec.helpers.Controller;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

import java.io.IOException;
import java.rmi.RemoteException;

public class Main extends Application {

    private Stage primaryStage;
    private BorderPane rootLayout;
    private Controller currentViewController;


    /**
     * Constructor
     */
    public Main() throws RemoteException {
    }

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        this.primaryStage.setTitle("Service Provider overview");
        initRootLayout();
        showMainView();

    }

    @Override
    public void stop() {

        System.out.println("Stage is Normaly closed");
    }


    public void initRootLayout() {
        try {
            // Load root layout from fxml file.
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(Main.class.getResource("RootMenu.fxml"));
            rootLayout = (BorderPane) loader.load();

            // Show the scene containing the root layout.
            Scene scene = new Scene(rootLayout);
            primaryStage.setScene(scene);
            //scene.getStylesheets().add("be.msec.stylesheet.css");


            // Give the controller access to the main app.
            RootMenuController controller = loader.getController();
            controller.setMain(this);
            currentViewController = controller;

            primaryStage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public Controller getCurrentViewController() {
        return currentViewController;
    }

    // --------------------- LOGIN VIEW ------------------------

    public void showMainView() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(Main.class.getResource("mainServiceView.fxml"));
            System.out.println("Loading Main Page");
            AnchorPane loginView = (AnchorPane) loader.load();
            //controller initialiseren + koppelen aan mainClient
            MainServiceController controller = loader.getController();
            controller.setMainController(this);
            currentViewController = controller;
            rootLayout.setCenter(loginView);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
