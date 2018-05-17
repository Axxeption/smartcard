package be.msec.controllers;
import java.util.ArrayList;

import be.msec.ServiceProvider;
import be.msec.ServiceProviderMain;
import be.msec.client.ServiceProviderType;
import be.msec.helpers.Controller;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.util.Callback;

public class MainServiceController extends Controller {

    @FXML
    private ComboBox<ServiceProvider> serviceProviderCombo;
    @FXML
    private TextArea outputTextArea;
    
    private ServiceProviderMain spMain;
    private ObservableList<ServiceProvider> services = FXCollections.observableArrayList();
    private ServiceProvider selectedServiceProvider;

    public MainServiceController() {

    }

    @FXML
    private void initialize() {
        serviceProviderCombo.setCellFactory(new Callback<ListView<ServiceProvider>, ListCell<ServiceProvider>>() {
            @Override
            public ListCell<ServiceProvider> call(ListView<ServiceProvider> p) {

                ListCell<ServiceProvider> cell = new ListCell<ServiceProvider>() {

                    @Override
                    protected void updateItem(ServiceProvider service, boolean empty) {
                        super.updateItem(service, empty);
                        if (service == null || empty) {
                            setGraphic(null);
                        } else {
                            setText(service.getInfo().getName());
                        }
                    }
                };
                return cell;
            }
        });
        serviceProviderCombo.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<ServiceProvider>() {
            @Override
            public void changed(ObservableValue<? extends ServiceProvider> observable, ServiceProvider oldValue, ServiceProvider newValue) {
                // Your action here
                if (newValue != null) {
                    selectedServiceProvider = newValue;

                }
            }
        });

    }

    private void generateSPs() {
        ArrayList<ServiceProvider> SPs = new ArrayList<>();
        //the bigger the maxRights the more they can ask
        ServiceProvider defaultSP = new ServiceProvider("Basic", ServiceProviderType.DEFAULT, 1);
        ServiceProvider party = new ServiceProvider("Party entrance", ServiceProviderType.DEFAULT, 1);
        ServiceProvider goksite = new ServiceProvider("Gok Site", ServiceProviderType.SOCNET, 2);
        
        ServiceProvider huisarts = new ServiceProvider("HuisArts", ServiceProviderType.HEALTHCARE, 3);
        ServiceProvider ziekenhuis = new ServiceProvider("ZNA Ziekenhuis", ServiceProviderType.HEALTHCARE, 3);
        ServiceProvider governmentSP = new ServiceProvider("Politie background check", ServiceProviderType.GOVERNMENT,4);
        ServiceProvider studentAtWork = new ServiceProvider("Student@Work", ServiceProviderType.GOVERNMENT,4);
        ServiceProvider belastingen = new ServiceProvider("Belastings aangiften", ServiceProviderType.GOVERNMENT,4);
        
        services.add(party);
        services.add(defaultSP);
        services.add(governmentSP);
        services.add(goksite);
        services.add(huisarts);
        services.add(ziekenhuis);
        services.add(studentAtWork);
        services.add(belastingen);
        
        SPs.addAll(services);
        
        spMain.setServiceProviders(SPs);
    }

    public void setMainController(ServiceProviderMain mainController) {
        this.spMain = mainController;
        
        generateSPs();
        serviceProviderCombo.setItems(services);
    }

    public void getDataGoverment(){
        getData(4);
    }
    public void getDataHealth() {
        getData(3);
    }
    public void getDataSocial(){
        getData(2);
    }
    
    public void getDataBasic() {
        getData(1);
    }
    
    private void getData(int query){
        if(selectedServiceProvider != null){    
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
