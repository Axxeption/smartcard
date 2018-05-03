package be.msec;

import java.io.Serializable;

import be.msec.client.MiddleWareAPI;

public class ServiceAction implements Serializable {

    String name;
    MiddleWareAPI command;
    
    public ServiceAction(String name, MiddleWareAPI command) {
        this.name = name;
        this.command =command;
    }
    
    
    public MiddleWareAPI getCommand() {
		return command;
	}


	public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
