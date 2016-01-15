/**
 * @author lcappuccio
 * @date 07/04/2015 17:25
 */
package org.systemexception.javakeystore.main;

import org.systemexception.javakeystore.exception.SignatureUtilException;
import org.systemexception.javakeystore.impl.SignatureUtilImpl;
import org.systemexception.javakeystore.pojo.ZipUtils;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Main {

	private static final String INPUT_PATH = "input/";
	public static final String OUTPUT_PATH = System.getProperty("user.dir") + "/target/";

	public static void main(String[] args) throws IOException, SignatureUtilException, KeyStoreException,
			NoSuchAlgorithmException, SignatureException, InvalidKeyException {

		String keyStorePath = INPUT_PATH + "client.jks";
		byte[] keyStorePasswd = "rcpxrcpx".getBytes();

		// Create keystore
		SignatureUtilImpl keystore = new SignatureUtilImpl(keyStorePath, keyStorePasswd);

		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		keystore.useKey(keyAlias, keyPasswd);

		// Read a document
		String loremIpsum = readTextFile(INPUT_PATH + "lorem_ipsum.txt");
		System.out.println("\n*** CLEAR TEXT DOCUMENT ***");
		System.out.println(loremIpsum);

		// Sign the document with the preselected key
		keystore.signDocument(loremIpsum);

		// Verify signature
		System.out.println("\n*** VERIFY SIGNATURE ***");
		System.out.println("Document signature is valid: " + keystore.verifySign(loremIpsum, keystore
				.getDocumentSignature()));
		assert (keystore.verifySign(loremIpsum, keystore.getDocumentSignature()));
		// Negative case
		System.out.println("Falsified document signature is valid: " + keystore.verifySign("Falsified document",
				keystore.getDocumentSignature()));
		assert (!keystore.verifySign("Falsified document", keystore.getDocumentSignature()));

		// Save document and signature to ZIP
		ZipUtils zipUtil = new ZipUtils();
		zipUtil.addFileToZip(new File(INPUT_PATH + "lorem_ipsum.txt"));
		File signatureFile = new File(OUTPUT_PATH + "lorem_ipsum.txt.sig");
		writeTextToFile(new String(keystore.getDocumentSignature()), signatureFile);
		zipUtil.addFileToZip(signatureFile);
		zipUtil.closeZip();
	}

	/**
	 * @param fileName the source file to read
	 * @return the document as string
	 * @throws UnsupportedEncodingException
	 * @throws IOException
	 */
	private static String readTextFile(String fileName) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(fileName));
		return new String(encoded, "UTF8");
	}

	/**
	 * @param text     the text document
	 * @param fileName the destination filename
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static void writeTextToFile(String text, File fileName) throws IOException {
		FileUtils.writeStringToFile(fileName, text);
	}
}
