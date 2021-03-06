package be.msec;

import java.io.Serializable;

import be.msec.client.SignedCertificate;

public class ServiceProviderAction implements Serializable {
	private ServiceAction action;
	private SignedCertificate certificate;
	private String serviceProvider;
	private short dataQuery;
	private byte[]challengeBytes;
	
	public ServiceProviderAction(ServiceAction action) {
		this.action = action;
	}
	public ServiceProviderAction(ServiceAction action, SignedCertificate certificate) {
		this.action = action;
		this.certificate = certificate;
	}
	
	public short getDataQuery() {
		return dataQuery;
	}
	public void setDataQuery(short dataQuery) {
		this.dataQuery = dataQuery;
	}
	public ServiceAction getAction() {
		return action;
	}

	public SignedCertificate getSignedCertificate() {
		return certificate;
	}

	public String getServiceProvider() {
		return serviceProvider;
	}

	public void setServiceProvider(String serviceProvider) {
		this.serviceProvider = serviceProvider;
	}

	public byte[] getChallengeBytes() {
		return challengeBytes;
	}

	public void setChallengeBytes(byte[] challengeBytes) {
		this.challengeBytes = challengeBytes;
	}
	
	
}
