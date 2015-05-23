/**
 * $Id$
 *
 * @author lcappuccio
 * @date 08/04/2015 12:20
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.impl;

import com.scytl.javakeystore.api.SignatureUtil;
import com.scytl.javakeystore.exception.SignatureUtilException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SignatureUtilImpl implements SignatureUtil {

	private KeyStore keyStore;
	private final Signature signature;
	private final ArrayList<PublicKey> publicKeys;
	private PrivateKey privateKey;
	private byte[] byteSignature;
	private final static String algorithm = "SHA256withRSA";
	private final static int signatureSize = 256;
	private FileInputStream inputStream;

	/**
	 * Initializes the object with a path to java key store and its password, see shell script to create the jks
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @throws SignatureUtilException
	 */
	public SignatureUtilImpl(String keyStorePath, byte[] keyStorePasswd) throws SignatureUtilException {
		ArrayList<Certificate> certificates = new ArrayList();
		ArrayList<String> certificateAliases = new ArrayList();
		this.publicKeys = new ArrayList();
		// Initialize keyStore
		openKeyStore(keyStorePath, keyStorePasswd);
		// Load certificates
		try {
			Enumeration enumeration = keyStore.aliases();
			while (enumeration.hasMoreElements()) {
				String alias = (String) enumeration.nextElement();
				certificateAliases.add(alias);
				certificates.add(keyStore.getCertificate(alias));
			}
			// Initialize signature and load certificates/public keys
			signature = Signature.getInstance(algorithm);
			for (Certificate certificate : certificates) {
				publicKeys.add(certificate.getPublicKey());
			}
		} catch (KeyStoreException | NoSuchAlgorithmException ex) {
			// Not testable because exceptions come not injectable/hardcoded variables
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 */
	private void openKeyStore(String keyStorePath, byte[] keyStorePasswd) throws SignatureUtilException {
		try {
			keyStore = KeyStore.getInstance("jks");
			inputStream = new FileInputStream(new File(keyStorePath));
			keyStore.load(inputStream, new String(keyStorePasswd).toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException ex) {
			throw new SignatureUtilException(ex.getMessage());
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException ex) {
					Logger.getLogger(SignatureUtilImpl.class.getName()).log(Level.SEVERE, null, ex);
				}
			}
		}
	}

	/**
	 * Preselects a private key in the jks
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 * @throws SignatureUtilException
	 */
	@Override
	public void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException {
		try {
			privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd);
			if (privateKey == null) {
				throw new SignatureUtilException("No such key in keystore");
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 * Initializes the signature object that will be used to verify against the external file signature
	 *
	 * @param document
	 * @throws SignatureUtilException
	 */
	@Override
	public void signDocument(String document) throws SignatureUtilException {
		if (document == null) {
			throw new SignatureUtilException("Trying to sign a null document");
		}
		try {
			signature.initSign(privateKey);
			signature.update(document.getBytes());
			byteSignature = signature.sign();
		} catch (InvalidKeyException | SignatureException ex) {
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 * Verifies the signature in the external file against the one obtained by the document/key pair
	 *
	 * @param document
	 * @param documentSignature
	 * @return
	 * @throws SignatureUtilException
	 */
	@Override
	public Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException {
		if (documentSignature.length != signatureSize) {
			throw new SignatureUtilException("Invalid signature size: " + documentSignature.length);
		}
		try {
			for (PublicKey publicKey : publicKeys) {
				signature.initVerify(publicKey);
				signature.update(document.getBytes());
				if (signature.verify(documentSignature)) {
					return true;
				}
			}
			return false;
		} catch (InvalidKeyException | SignatureException ex) {
			throw new SignatureUtilException(ex.getMessage());
		}
	}

	/**
	 *
	 * @return
	 */
	public byte[] getDocumentSignature() {
		return byteSignature;
	}
}
