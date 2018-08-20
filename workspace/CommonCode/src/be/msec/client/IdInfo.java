package be.msec.client;

import java.io.Serializable;

public class IdInfo implements Serializable{
	//evt nog signature apart toevoegen

	private static final long serialVersionUID = 1L;
	private String info;
	
	public IdInfo(String info) {
		this.info = info;
	}
	
	public void setInfo(String info) {
		this.info = info;
	}
	public String getInfo() {
		return this.info;
	}
}
