package be.msec;

import java.io.Serializable;

import be.msec.client.OwnCertificate;

public class ServiceProviderAction implements Serializable {
	private ServiceAction action;
	private OwnCertificate certificate;
	
	public ServiceProviderAction(ServiceAction action, OwnCertificate certificate) {
		this.action = action;
		this.certificate = certificate;
	}

	public ServiceAction getAction() {
		return action;
	}

	public OwnCertificate getCertificate() {
		return certificate;
	}
	
	
}
