/**
 * @author lcappuccio
 * @date 08/04/2015 12:20
 */
package org.systemexception.javakeystore.impl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.systemexception.javakeystore.api.SignatureUtil;
import org.systemexception.javakeystore.exception.SignatureUtilException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;

public class SignatureUtilImpl implements SignatureUtil {

	private final static Logger logger = LogManager.getLogger(SignatureUtilImpl.class);
	private final String algorithm = "SHA256withRSA";
	private final int signatureSize = 256;
	private Signature signature;
	private final ArrayList<PublicKey> publicKeys;
	private KeyStore keyStore;
	private PrivateKey privateKey;
	private byte[] byteSignature;

	/**
	 * Initializes the object with a path to java key store and its password, see shell script to create the jks
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws CertificateException
	 */
	public SignatureUtilImpl(String keyStorePath, byte[] keyStorePasswd) throws NoSuchAlgorithmException,
			KeyStoreException, IOException, CertificateException {
		ArrayList<Certificate> certificates = new ArrayList();
		this.publicKeys = new ArrayList();
		// Initialize keyStore
		openKeyStore(keyStorePath, keyStorePasswd);
		// Load certificates
		Enumeration enumeration = keyStore.aliases();
		while (enumeration.hasMoreElements()) {
			String alias = (String) enumeration.nextElement();
			certificates.add(keyStore.getCertificate(alias));
		}
		// Initialize signature and load certificates/public keys
		signature = Signature.getInstance(algorithm);
		for (Certificate certificate : certificates) {
			publicKeys.add(certificate.getPublicKey());
		}
	}

	/**
	 * @param keyStorePath   the keystore path
	 * @param keyStorePasswd the keystore password
	 */
	private void openKeyStore(String keyStorePath, byte[] keyStorePasswd) throws IOException,
			KeyStoreException, CertificateException, NoSuchAlgorithmException {
		FileInputStream inputStream;
		logger.info("Opening " + keyStorePath);
		keyStore = KeyStore.getInstance("jks");
		inputStream = new FileInputStream(new File(keyStorePath));
		keyStore.load(inputStream, new String(keyStorePasswd).toCharArray());
		inputStream.close();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException {
		logger.info("Using key " + keyAlias);
		try {
			privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
			if (privateKey == null) {
				exceptionHandler(new SignatureUtilException("Bad key"), "Bad key");
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void signDocument(String document) throws SignatureUtilException, InvalidKeyException, SignatureException {
		logger.info("Signing document");
		if (document == null) {
			String errorMessage = "Trying to sign a null document";
			exceptionHandler(new SignatureUtilException(errorMessage), errorMessage);
		}
		signature.initSign(privateKey);
		signature.update(document != null ? document.getBytes() : new byte[0]);
		byteSignature = signature.sign();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException,
			InvalidKeyException, SignatureException {
		logger.info("Asked to verify document signature");
		if (documentSignature.length != signatureSize) {
			String errorMessage = "Invalid signature size: ";
			exceptionHandler(new SignatureUtilException(errorMessage + documentSignature.length),
					errorMessage + documentSignature.length);
		}
		for (PublicKey publicKey : publicKeys) {
			signature.initVerify(publicKey);
			signature.update(document.getBytes());
			if (signature.verify(documentSignature)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return the document signature
	 */
    @Override
	public byte[] getDocumentSignature() {
		return byteSignature;
	}

	/**
	 * Handle exception
	 *
	 * @param exception the exception
	 * @param message   the message of the exception
	 */
	private void exceptionHandler(Exception exception, String message) throws SignatureUtilException {
		logger.error(message, exception);
		throw new SignatureUtilException(exception.getMessage());
	}
}
