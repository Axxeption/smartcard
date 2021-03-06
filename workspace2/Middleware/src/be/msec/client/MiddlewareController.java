package be.msec.client;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import be.msec.client.MiddlewareMain;
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
			}else {
				message ="Wrong Pin!";
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
