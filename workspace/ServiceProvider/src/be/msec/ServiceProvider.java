package be.msec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

import be.msec.client.CAService;
import be.msec.client.InfoStruct;
import be.msec.client.OwnCertificate;
import be.msec.client.ServiceProviderInfoStruct;
import be.msec.client.ServiceProviderType;

public class ServiceProvider {
	ServiceProviderInfoStruct serviceProviderInfo;
	RSAPrivateKey privateKey;
	OwnCertificate certificate;


    public ServiceProvider(String name, ServiceProviderType type) {
    		KeyPair keyPair = generateKey();
	        privateKey = (RSAPrivateKey) keyPair.getPrivate();
	        serviceProviderInfo = new ServiceProviderInfoStruct(keyPair.getPublic(), name);
	        letCASignCertificate();
    }

    private KeyPair generateKey() {
		try {
			 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			 keyGen.initialize(1024);
	        // Generate Key Pairs, a private key and a public key.
	        return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
    }
    
    private void letCASignCertificate() {
    	InfoStruct infoStruct = serviceProviderInfo;
		certificate = CAService.getSignedCertificate(infoStruct);
		System.out.println(certificate.verifySignature(CAService.getPublicKey()));
    }


	public ServiceProviderInfoStruct getInfo() {
		return serviceProviderInfo;
	}


	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}
	
	public PublicKey getPublicKey() {
		return serviceProviderInfo.getPublicKey();
	}
	
	public OwnCertificate getCertificate() {
		return certificate;
	}

	@Override
	public String toString() {
		return "ServiceProvider [name=" + serviceProviderInfo.getName() + " validTime=" + serviceProviderInfo.getValidTime()  + " type=" + serviceProviderInfo.getType() + ", privateKey=" + privateKey
				+ ", certificate=" + certificate + "]";
	}
    
    
    

}
