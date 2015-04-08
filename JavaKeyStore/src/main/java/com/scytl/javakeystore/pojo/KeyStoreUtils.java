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
package com.scytl.javakeystore.pojo;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import sun.misc.BASE64Encoder;

public class KeyStoreUtils {

	private KeyStore keyStore;
	private Signature signature;
	private final List<Certificate> certificates = new ArrayList();
	private final List<PublicKey> publicKeys;
	private final ArrayList<String> certificateAliases = new ArrayList();

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @throws Exception
	 */
	public KeyStoreUtils(String keyStorePath, String keyStorePasswd)
			throws Exception {
		this.publicKeys = new ArrayList();
		keyStore = openKeyStore(keyStorePath, keyStorePasswd);
		buildCertificates();
		buildPublicKeys();
	}

	/**
	 *
	 * @param keyStorePath
	 * @param keyStorePasswd
	 * @return
	 * @throws Exception
	 */
	private KeyStore openKeyStore(String keyStorePath, String keyStorePasswd)
			throws Exception {
		keyStore = KeyStore.getInstance("jks");
		FileInputStream inputStream = new FileInputStream(new File(keyStorePath));
		keyStore.load(inputStream, keyStorePasswd.toCharArray());
		return keyStore;
	}

	/**
	 *
	 * @throws Exception
	 */
	private void buildCertificates() throws Exception {
		Enumeration enumeration = keyStore.aliases();
		while (enumeration.hasMoreElements()) {
			String alias = (String) enumeration.nextElement();
			certificateAliases.add(alias);
			certificates.add(keyStore.getCertificate(alias));
		}
	}

	/**
	 *
	 * @throws Exception
	 */
	private void buildPublicKeys() throws Exception {
		signature = Signature.getInstance("SHA256withRSA");
		for (Certificate certificate : certificates) {
			publicKeys.add(certificate.getPublicKey());
		}
	}

	/**
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 * @return
	 * @throws Exception
	 */
	public PrivateKey getPrivateKey(String keyAlias, String keyPasswd) throws Exception {
		PrivateKey key = (PrivateKey) keyStore.getKey(keyAlias, keyPasswd.toCharArray());
		return key;
	}

	/**
	 *
	 * @param key
	 * @return
	 */
	public String getDecodedPrivateKey(PrivateKey key) {
		return new BASE64Encoder().encode(key.getEncoded());
	}

	/**
	 * 
	 * @param document
	 * @param privateKey
	 * @return
	 * @throws Exception 
	 */
	public byte[] signDocument(String document, PrivateKey privateKey) throws Exception {
		signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(document.getBytes());
		return signature.sign();
	}
	
	/**
	 * 
	 * @param signedDocument
	 * @param publicKey
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException 
	 */
	public Boolean verifySign(String document, byte[] signedDocument, PublicKey publicKey) throws Exception {
		signature.initVerify(publicKey);
		signature.update(document.getBytes());
		return signature.verify(signedDocument);
	}

	public List<PublicKey> getPublicKeys() {
		return publicKeys;
	}

	public ArrayList<String> getCertificateAliases() {
		return certificateAliases;
	}

	public Certificate getCertificateForAlias(String alias) throws KeyStoreException {
		return keyStore.getCertificate(alias);
	}

}
