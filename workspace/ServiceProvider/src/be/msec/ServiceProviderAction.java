package be.msec;

import java.io.Serializable;

import be.msec.client.SignedCertificate;

public class ServiceProviderAction implements Serializable {
	private ServiceAction action;
	private SignedCertificate certificate;
	
	public ServiceProviderAction(ServiceAction action, SignedCertificate certificate) {
		this.action = action;
		this.certificate = certificate;
	}

	public ServiceAction getAction() {
		return action;
	}

	public SignedCertificate getSignedCertificate() {
		return certificate;
	}
	
	
}
