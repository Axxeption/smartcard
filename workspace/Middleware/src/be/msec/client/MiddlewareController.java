package be.msec.client;

import javafx.event.ActionEvent;

import javafx.application.Application;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;

public class MiddlewareController {
	MiddlewareMain main;
	
	public MiddlewareController(MiddlewareMain c) {
		System.out.println("Controller set!");
		this.main = c;
	}
	
	public void askName(ActionEvent event) {
		main.askName();
	}
}
