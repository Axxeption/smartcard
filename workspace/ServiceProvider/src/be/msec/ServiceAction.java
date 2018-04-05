package be.msec;

import java.io.Serializable;

import be.msec.client.CallableMiddelwareMethodes;

public class ServiceAction implements Serializable {

    String name;
    CallableMiddelwareMethodes command;
    
    public ServiceAction(String name, CallableMiddelwareMethodes command) {
        this.name = name;
        this.command =command;
    }
    
    
    public CallableMiddelwareMethodes getCommand() {
		return command;
	}


	public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
