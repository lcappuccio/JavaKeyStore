/**
 * $Id$
 *
 * @author lcappuccio
 * @date 07/04/2015 17:33
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.pojo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.misc.BASE64Encoder;

public class RCPKeyStore {

	private static final Logger logger = Logger.getLogger(RCPKeyStore.class.getCanonicalName());

	private final String keyStorePath, keyStorePassword, keyPasswd;
	private String decodedKey;
	private final HashMap<String, Certificate> keyAlias = new HashMap();
	private File keyStoreFile;
	private KeyStore keystore;
	private PrivateKey privateKey;

	public RCPKeyStore(String path, String keyStorePasswd, String keyPasswd) throws KeyStoreException {
		this.keyStorePath = path;
		this.keyStorePassword = keyStorePasswd;
		this.keyPasswd = keyPasswd;
		keyStoreFile = openKeyStoreFile(keyStorePath);
		keystore = openKeyStore();
		printKeyStoreInfo();
		openKeys();
	}

	public HashMap<String, Certificate> getKeyAlias() {
		return keyAlias;
	}
	
	public Key getKey() {
		return privateKey;
	}

	/**
	 *
	 * @param keyPath
	 * @return
	 * @throws RuntimeException
	 */
	private File openKeyStoreFile(String keyPath) throws RuntimeException {
		keyStoreFile = new File(keyPath);
		System.out.println("Opening " + keyPath);
		if (!keyStoreFile.exists()) {
			throw new RuntimeException("Missing client keystore");
		}
		return keyStoreFile;
	}

	/**
	 *
	 * @return
	 */
	public KeyStore openKeyStore() {
		try {
			keystore = KeyStore.getInstance("jks");
			FileInputStream inputStream = new FileInputStream(keyStoreFile);
			keystore.load(inputStream, keyStorePassword.toCharArray());
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
			logger.log(Level.SEVERE, ex.getMessage());
		}
		return keystore;
	}
	
	private void printKeyStoreInfo() {
		try {
			Enumeration enumeration = keystore.aliases();
			while (enumeration.hasMoreElements()) {
				String alias = (String) enumeration.nextElement();
				keyAlias.put(alias, keystore.getCertificate(alias));
				System.out.println("alias name: " + alias);
				Certificate certificate = keystore.getCertificate(alias);
				System.out.println(certificate.toString());
			}
		} catch (KeyStoreException ex) {
			logger.log(Level.SEVERE, ex.getMessage());
		}
	}
	
	private void openKeys() {
		try {
			this.privateKey = (PrivateKey) keystore.getKey("client", "rcpx".toCharArray());
			this.decodedKey = new BASE64Encoder().encode(privateKey.getEncoded());
			System.out.println("Decoded key:\n" + decodedKey);
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
			logger.log(Level.SEVERE, ex.getMessage());
		}
	}
}
