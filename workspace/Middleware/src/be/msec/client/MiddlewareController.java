package be.msec.client;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.application.Application;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;

public class MiddlewareController  {
	MiddlewareMain main;
	
	@FXML
	private TextField pin_textfield;
	@FXML
	private Label outputLabel;
	
	public MiddlewareController() {
	}
	
	public void setMain(MiddlewareMain m) {
		this.main = m;
	}
	
	public void validatePin(){
		byte[] pinInBytes = pin_textfield.getText().getBytes();
		String message;
		try {
			if(main.loginWithPin(pinInBytes)) {
				message = "Correct Pin!";	
				pin_textfield.setStyle("-fx-control-inner-background: #7CFC00");
			}else {
				message ="Wrong Pin!";
				pin_textfield.setStyle("-fx-control-inner-background: #FF0000");
			}
		} catch (Exception e) {
			message = e.getMessage();
			e.printStackTrace();
			
		}
		outputLabel.setText(message);
	}
	
	
	public void setMainMessage(String msg) {
		outputLabel.setText(msg);
	}
	
	public void askName(ActionEvent event) {
		main.askName();
	}
}
