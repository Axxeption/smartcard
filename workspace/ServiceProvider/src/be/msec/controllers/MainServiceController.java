package be.msec.controllers;
import java.util.ArrayList;

import be.msec.ServiceAction;
import be.msec.ServiceProvider;
import be.msec.ServiceProviderAction;
import be.msec.ServiceProviderMain;
import be.msec.client.MiddleWareAPI;
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
    private TextArea outputTextArea;
    @FXML
    private Button getData;

    private ServiceProviderMain spMain;
    private ObservableList<ServiceProvider> services = FXCollections.observableArrayList();
    private ServiceProvider selectedServiceProvider;


    public MainServiceController() {

    }

    @FXML
    private void initialize() {
        getData.setDefaultButton(true);
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

    }

    private void setEnterEventHandler(Node root) {
        root.addEventHandler(KeyEvent.KEY_PRESSED, ev -> {
            if (ev.getCode() == KeyCode.ENTER) {
                getData.fire();
                ev.consume();
            }
        });
    }
    private void generateSPs() {
    	ArrayList<ServiceProvider> SPs = new ArrayList<>();
    	//the bigger the maxRights the more they can ask
    	ServiceProvider napoleonGames = new ServiceProvider("napoleonGames", ServiceProviderType.OWN, 2);
    	ServiceProvider defaultSP = new ServiceProvider("default", ServiceProviderType.DEFAULT, 1);
    	ServiceProvider facebook = new ServiceProvider("Facebook", ServiceProviderType.SOCNET,3);
    	ServiceProvider governmentSP = new ServiceProvider("Belgium", ServiceProviderType.GOVERNMENT,4);
    	
    	services.add(napoleonGames);
    	services.add(defaultSP);
    	services.add(governmentSP);
    	services.add(facebook);
    	SPs.add(napoleonGames);
    	SPs.add(defaultSP);
    	SPs.add(governmentSP);
    	SPs.add(facebook);
    	
    	spMain.setServiceProviders(SPs);
    }

    public void setMainController(ServiceProviderMain mainController) {
        this.spMain = mainController;
        //test data in services steken
        generateSPs();
        serviceList.setItems(services);
    }

    public void getData_egov(){
    	getData(4);
    }
    public void getData_socnet(){
    	getData(3);
    }
    
    public void getData_default() {
    	getData(1);
    }
    
    public void getData_own() {
    	getData(2);
    }
    	
    private void getData(int query){
        if(selectedServiceProvider != null){	
            addToDataLog(selectedServiceProvider.toString() + "-> get data ; type = " + selectedServiceProvider.getInfo().getType());
            addToDataLog("Sending request for data: " + query);
            spMain.submitDataQuery(selectedServiceProvider, query);

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
