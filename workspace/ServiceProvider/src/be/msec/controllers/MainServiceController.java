package be.msec.controllers;
import java.util.ArrayList;

import be.msec.ServiceAction;
import be.msec.ServiceProvider;
import be.msec.ServiceProviderAction;
import be.msec.ServiceProviderMain;
import be.msec.client.CallableMiddelwareMethodes;
import be.msec.client.ServiceProviderType;
import be.msec.helpers.Controller;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.util.Callback;

public class MainServiceController extends Controller {

    @FXML
    private ListView<ServiceProvider> serviceList;
    @FXML
    private ListView<ServiceAction> actionList;
    @FXML
    private TextArea outputTextArea;
    @FXML
    private Button submit;

    private ServiceProviderMain spMain;
    private ObservableList<ServiceProvider> services = FXCollections.observableArrayList();
    private ObservableList<ServiceAction> actions = FXCollections.observableArrayList();
    private ServiceProvider selectedServiceProvider;
    private ServiceAction selectedServiceAction;


    public MainServiceController() {

    }

    @FXML
    private void initialize() {
        submit.setDefaultButton(true);
        serviceList.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        serviceList.setCellFactory(new Callback<ListView<ServiceProvider>, ListCell<ServiceProvider>>() {
            @Override
            public ListCell<ServiceProvider> call(ListView<ServiceProvider> p) {

                ListCell<ServiceProvider> cell = new ListCell<ServiceProvider>() {

                    @Override
                    protected void updateItem(ServiceProvider service, boolean bln) {
                        super.updateItem(service, bln);
                        if (service != null) {
                                setText(service.getInfo().getName());

                        }
                    }
                };
                return cell;
            }
        });
        serviceList.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<ServiceProvider>() {
            @Override
            public void changed(ObservableValue<? extends ServiceProvider> observable, ServiceProvider oldValue, ServiceProvider newValue) {
                // Your action here
                if (newValue != null) {
                    selectedServiceProvider = newValue;

                }
            }
        });

        actionList.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        actionList.setCellFactory(new Callback<ListView<ServiceAction>, ListCell<ServiceAction>>() {
            @Override
            public ListCell<ServiceAction> call(ListView<ServiceAction> p) {

                ListCell<ServiceAction> cell = new ListCell<ServiceAction>() {

                    @Override
                    protected void updateItem(ServiceAction action, boolean bln) {
                        super.updateItem(action, bln);
                        if (action != null) {
                            setText(action.getName());

                        }
                    }
                };
                return cell;
            }
        });
        actionList.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<ServiceAction>() {
            @Override
            public void changed(ObservableValue<? extends ServiceAction> observable, ServiceAction oldValue, ServiceAction newValue) {
                // Your action here
                if (newValue != null) {
                    selectedServiceAction = newValue;

                }
            }
        });

    }

    private void setEnterEventHandler(Node root) {
        root.addEventHandler(KeyEvent.KEY_PRESSED, ev -> {
            if (ev.getCode() == KeyCode.ENTER) {
                submit.fire();
                ev.consume();
            }
        });
    }
    private void generateSPs() {
    	ArrayList<ServiceProvider> SPs = new ArrayList<>();
    	ServiceProvider napoleonGames = new ServiceProvider("napoleonGames", ServiceProviderType.SOCNET);
    	ServiceProvider studentAtWork = new ServiceProvider("studentAtWork", ServiceProviderType.GOVERNMENT);
    	ServiceProvider kompasKlub = new ServiceProvider("KompasKlub", ServiceProviderType.DEFAULT);
    	
    	services.add(napoleonGames);
    	services.add(studentAtWork);
    	services.add(kompasKlub);
    	SPs.add(napoleonGames);
    	SPs.add(studentAtWork);
    	SPs.add(kompasKlub);
    	
    	spMain.setServiceProviders(SPs);
    }

    public void setMainController(ServiceProviderMain mainController) {
        this.spMain = mainController;
        //test data in services steken
        generateSPs();
        actions.add(new ServiceAction("authenticate SP",CallableMiddelwareMethodes.AUTH_SP));
        actions.add(new ServiceAction("get Data",CallableMiddelwareMethodes.GET_DATA));

        serviceList.setItems(services);
        actionList.setItems(actions);
    }

    public void submit(){
        if(selectedServiceProvider != null && selectedServiceAction !=null){
            ServiceProviderAction request = new ServiceProviderAction(selectedServiceAction, selectedServiceProvider.getCertificate());
            addToDataLog(selectedServiceProvider.toString());
            addToDataLog(selectedServiceAction.getName());
            addToDataLog("Sending request...");
            request.setServiceProvider(selectedServiceProvider.getName());
            spMain.sendServiceProviderActionToMiddleWare(request);
            
        }else {	
        	addToDataLog("Select a ServiceProvider and an action!");
        }

    }
    

    public void addToDataLog(String log) {
    	System.out.println(log);
    	outputTextArea.setText(outputTextArea.getText()+"\n"+log);
    }

    public void alertDialog(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Information Dialog");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }
}
