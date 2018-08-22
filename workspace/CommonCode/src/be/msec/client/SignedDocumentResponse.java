package be.msec.client;

import java.io.Serializable;

public class SignedDocumentResponse implements Serializable{

	//terugzenden van gesignede hash + certificaat (=response) + oorspronkelijke bericht en hash zodat de hash zelf ook gecontroleerd kan worden

	private byte[] response; //nog samengeplakt cert (length 136) + gesignede hash
	private byte[] unsignedDocument; // volledig plain doc
	private byte[] documentHash; //om hash te controleren met doc
	
	public byte[] getResponse() {
		return response;
	}

	public void setResponse(byte[] response) {
		this.response = response;
	}

	public byte[] getUnsignedDocument() {
		return unsignedDocument;
	}

	public void setUnsignedDocument(byte[] unsignedDocument) {
		this.unsignedDocument = unsignedDocument;
	}

	public byte[] getDocumentHash() {
		return documentHash;
	}

	public void setDocumentHash(byte[] documentHash) {
		this.documentHash = documentHash;
	}

	
	
	public SignedDocumentResponse(byte[] response, byte[] unsignedDocument, byte[] documentHash) {
		super();
		this.response = response;
		this.unsignedDocument = unsignedDocument;
		this.documentHash = documentHash;
	}
	
	
}
