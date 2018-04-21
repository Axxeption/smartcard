package be.msec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

import be.msec.client.CAService;
import be.msec.client.CertificateBasic;
import be.msec.client.SignedCertificate;
import be.msec.client.CertificateServiceProvider;
import be.msec.client.ServiceProviderType;

public class ServiceProvider {
	CertificateServiceProvider serviceProviderInfo;
	RSAPrivateKey privateKey;
	SignedCertificate certificate;
	String name;


    public ServiceProvider(String name, ServiceProviderType type, int maxRight) {
    		this.name = name;
    		KeyPair keyPair = generateKey();
	        privateKey = (RSAPrivateKey) keyPair.getPrivate();
	        //TODO choose maxRight for each serviceprovider 4 is hoogste (=gov), 1 laagste (=default)
	        serviceProviderInfo = new CertificateServiceProvider(keyPair.getPublic(), name, (short) maxRight);
	        letCASignCertificate();
    }

    private KeyPair generateKey() {
		try {
			 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			 keyGen.initialize(512);
	        // Generate Key Pairs, a private key and a public key.
	        return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
    }
    
    private void letCASignCertificate() {
    	CertificateBasic infoStruct = serviceProviderInfo;
		certificate = CAService.getSignedCertificate(infoStruct);
		System.out.println(certificate.verifySignature(CAService.getPublicKey()));
    }


	public CertificateServiceProvider getInfo() {
		return serviceProviderInfo;
	}


	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public PublicKey getPublicKey() {
		return serviceProviderInfo.getPublicKey();
	}
	
	public SignedCertificate getCertificate() {
		return certificate;
	}

	@Override
	public String toString() {
		return "ServiceProvider [name=" + serviceProviderInfo.getName() + " validTime=" + serviceProviderInfo.getValidTime()  + " type=" + serviceProviderInfo.getType() + ", privateKey=" + privateKey
				+ ", certificate=" + certificate + "]";
	}
    
    
    

}
