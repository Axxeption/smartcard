package be.msec;
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

    private Main mainController;
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
                                setText(service.getName());

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

    public void setMainController(Main mainController) {
        this.mainController = mainController;
        //test data in services steken
        services.add(new ServiceProvider("test Provider"));
        actions.add(new ServiceAction("test action"));

        serviceList.setItems(services);
        actionList.setItems(actions);
    }

    public void submit(){
        if(selectedServiceAction !=null){
            System.out.println(selectedServiceAction.getName());
            outputTextArea.setText(outputTextArea.getText()+"\n"+selectedServiceAction.getName());

        }
        if(selectedServiceProvider != null){
            System.out.println(selectedServiceProvider.getName());
            outputTextArea.setText(outputTextArea.getText()+"\n"+selectedServiceProvider.getName());
        }

    }







    public void alertDialog(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Information Dialog");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }


}
