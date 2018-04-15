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
        serviceList.setItems(services);
    }

    public void getData_egov(){
    	getData(7);
    }
    public void getData_socnet(){
    	getData(2);
    }
    
    public void getData_default() {
    	getData(0);
    }
    
    private void getData(int query){
        if(selectedServiceProvider != null){
            ServiceProviderAction request = new ServiceProviderAction(new ServiceAction("Get Data",CallableMiddelwareMethodes.AUTH_SP), selectedServiceProvider.getCertificate());
            addToDataLog(selectedServiceProvider.toString() + "-> get data ; type = " + selectedServiceProvider.getInfo().getType());
            addToDataLog("Sending request...");
            request.setServiceProvider(selectedServiceProvider.getName());
            request.setDataQuery((short) query);
            spMain.sendCommandToMiddleware(request,true);
            
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
