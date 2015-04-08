/**
 * $Id$
 *
 * @author lcappuccio
 * @date 07/04/2015 17:25
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.main;

import com.scytl.javakeystore.pojo.KeyStoreUtils;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class Main {

	private static KeyStoreUtils keystore;

	public static void main(String[] args) throws Exception {
		String keyStorePath = "src/main/resources/client.jks";
		String keyStorePasswd = "rcpxrcpx";
		// Create keystore
		keystore = new KeyStoreUtils(keyStorePath, keyStorePasswd);
		// Get certificate aliases
		ArrayList<String> certificateAliases = keystore.getCertificateAliases();
		for (String certificateAliase : certificateAliases) {
			System.out.println("Certificate alias in keystore: " + certificateAliase);
		}
		// Get public keys
		List<PublicKey> publicKeys = keystore.getPublicKeys();
		for (PublicKey publicKey : publicKeys) {
			System.out.println("Public key algorithms in keystore: " + publicKey.getAlgorithm());
		}
		// Get private keys
		String keyAlias = "client";
		String keyPasswd = "rcpx";
		PrivateKey privateKey = keystore.getPrivateKey(keyAlias, keyPasswd);
		String decodedKey = keystore.getDecodedPrivateKey(privateKey);
		System.out.println("Private key: " + decodedKey);
		
		// Read a document
		String loremIpsum = readTextFileToString("src/main/resources/lorem_ipsum.txt");
		System.out.println("\n*** CLEAR TEXT DOCUMENT ***");
		System.out.println(loremIpsum);
		
		// Sign with the first certificate
		System.out.println("\n*** SIGNED DOCUMENT ***");
		Certificate certificate = keystore.getCertificateForAlias(certificateAliases.get(0));
		byte[] signedDocument = keystore.signDocument(loremIpsum, privateKey);
		System.out.println(new String(signedDocument));
		
		// Verify signature
		System.out.println("\n*** VERIFY SIGNATURE ***");
		System.out.println(keystore.verifySign(loremIpsum, signedDocument, publicKeys.get(0)));
		System.exit(0);
	}

	private static String readTextFileToString(String fileName) throws UnsupportedEncodingException, IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(fileName));
		return new String(encoded, "UTF8");
	}
}
