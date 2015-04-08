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
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.codec.binary.Hex;

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

		// TODO Change to byte array
		String decodedKey = keystore.getDecodedPrivateKey(privateKey);
		System.out.println("Private key:\n" + decodedKey);

		// Read a document
		String loremIpsum = readTextFile("src/main/resources/lorem_ipsum.txt");
		System.out.println("\n*** CLEAR TEXT DOCUMENT ***");
		System.out.println(loremIpsum);

		// Sign with the first certificate
		System.out.println("\n*** SIGNATURE ***");
		byte[] documentSignature = keystore.getSignature(loremIpsum, privateKey);
		System.out.println(Hex.encodeHexString(documentSignature));

		// Verify signature
		System.out.println("\n*** VERIFY SIGNATURE ***");
		System.out.println("Document signature is valid: " + keystore.verifySign(loremIpsum, documentSignature, publicKeys.get(0)));

		// Save document and signature to ZIP
		System.exit(0);
	}

	private static String readTextFile(String fileName) throws UnsupportedEncodingException, IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(fileName));
		return new String(encoded, "UTF8");
	}
}
