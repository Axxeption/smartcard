package be.msec;
import be.msec.client.Challenge;
import be.msec.client.TimeInfoStruct;
import be.msec.controllers.MainServiceController;
import be.msec.controllers.RootMenuController;
import be.msec.helpers.Controller;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.RemoteException;

public class ServiceProviderMain extends Application {

    private Stage primaryStage;
    private BorderPane rootLayout;
    private Controller currentViewController;
    private MainServiceController mainController;
	private Socket serviceProviderSocket = null;
	static final int portSP = 8003;


    /**
     * Constructor
     */
    public ServiceProviderMain() throws RemoteException {
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
        connectToMiddleWare();
    }

    @Override
    public void stop() {

        System.out.println("Stage is Normaly closed");
    }
    
    public void sendServiceProviderActionToMiddleWare(ServiceProviderAction action) {
		ObjectOutputStream objectoutputstream = null;
		
		try {
			System.out.println("Send something to the middleware");
			objectoutputstream = new ObjectOutputStream(serviceProviderSocket.getOutputStream());
			objectoutputstream.writeObject(action);
			
			//wait for response
			receiveResponseFromMiddleWare();
			
		}catch (Exception e) {
			System.out.println(e);
		}
    }
    public void receiveResponseFromMiddleWare() {	
    	ObjectInputStream objectinputstream = null;
    	Object obj = null;
    	try {
			objectinputstream = new ObjectInputStream(serviceProviderSocket.getInputStream());
			
			if((Challenge)objectinputstream.readObject()!=null) {
				System.out.println("read obj");
				Challenge challengeFromSC = (Challenge)objectinputstream.readObject();
				System.out.println("received challenge "+challengeFromSC.toString());
				mainController.addToDataLog("Succesfully received challenge: " );
			} 
//			else if( (String)objectinputstream.readObject() != null) {
//				String answer = (String)objectinputstream.readObject();
//				System.out.println("received string "+answer);
//				mainController.addToDataLog("Succesfully received: " +answer);
//
//			}
//				
				
			
			
			
			System.out.println("succesfully received an answer!");
			
    	}catch (Exception e) {
			System.out.println(e);
		}
    }
    public void connectToMiddleWare() {
    	try {
			serviceProviderSocket = new Socket("localhost", portSP);
		} catch (IOException ex) {
			System.out.println("CANNOT CONNECT TO MIDDLEWARE " + ex);
		}
		System.out.println("Serviceprovider connected to middleware: " + serviceProviderSocket);

    }
    public void initRootLayout() {
        try {
            // Load root layout from fxml file.
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(ServiceProviderMain.class.getResource("RootMenu.fxml"));
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
            loader.setLocation(ServiceProviderMain.class.getResource("mainServiceView.fxml"));
            System.out.println("Loading Main Page");
            AnchorPane loginView = (AnchorPane) loader.load();
            //controller initialiseren + koppelen aan mainClient
            MainServiceController controller = loader.getController();
            controller.setMainController(this);
            currentViewController = controller;
            mainController = controller;
            rootLayout.setCenter(loginView);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
