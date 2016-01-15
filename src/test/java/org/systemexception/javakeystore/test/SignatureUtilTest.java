/**
 * @author lcappuccio
 * @date 09/04/2015 12:12
 */
package org.systemexception.javakeystore.test;

import org.systemexception.javakeystore.exception.SignatureUtilException;
import org.systemexception.javakeystore.impl.SignatureUtilImpl;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureUtilTest {

	private SignatureUtilImpl sut;
	private final static String keyStore = "client.jks";
	private static String keyStorePath;

	@BeforeClass
	public static void setUp() throws URISyntaxException {
		URL keyStoreURL = ClassLoader.getSystemResource(keyStore);
		File keyStoreFile = new File(keyStoreURL.toURI());
		keyStorePath = keyStoreFile.getAbsolutePath();
	}

	@Test(expected = FileNotFoundException.class)
	public void throwExceptionNotExistingFile() throws SignatureUtilException, NoSuchAlgorithmException,
			KeyStoreException, IOException, CertificateException {
		sut = new SignatureUtilImpl("abc", "somepassword".getBytes());
	}

	@Test(expected = IOException.class)
	public void wrongKeyStorePasswordException() throws SignatureUtilException, NoSuchAlgorithmException,
			KeyStoreException, IOException, CertificateException {
		sut = new SignatureUtilImpl(keyStorePath, "abc".getBytes());
	}

	@Test(expected = SignatureUtilException.class)
	public void nonExistingKeyAliasDisplaysError() throws SignatureUtilException, NoSuchAlgorithmException,
			KeyStoreException, IOException, CertificateException {
		sut = new SignatureUtilImpl(keyStorePath, "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "some_missing_key_alias";
		char[] keyPasswd = "some_nonexisting_pwd".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

	@Test(expected = SignatureUtilException.class)
	public void askToSignNullDocumentThrowsException() throws SignatureUtilException, SignatureException,
			InvalidKeyException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		sut.signDocument(null);
	}

	@Test(expected = SignatureUtilException.class)
	public void throwExceptionOnBadSignature() throws SignatureUtilException, SignatureException, InvalidKeyException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		// Tamper the signature
		byte[] testSignature = sut.getDocumentSignature();
		sut.verifySign(testDocument, Arrays.copyOf(testSignature, testSignature.length - 5));
	}

	@Test(expected = SignatureUtilException.class)
	public void throwExceptionOnBadKeyPassword() throws SignatureUtilException, NoSuchAlgorithmException,
			KeyStoreException, IOException, CertificateException {
		sut = new SignatureUtilImpl(keyStorePath, "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx_WRONG".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

	@Test
	public void askToVerifyDocument() throws SignatureUtilException, SignatureException, InvalidKeyException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertTrue(sut.verifySign(testDocument, sut.getDocumentSignature()));
	}

	@Test
	public void askToVerifyDocumentWithBadSignature() throws SignatureUtilException, SignatureException,
			InvalidKeyException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertFalse(sut.verifySign(testDocument, new byte[256]));
	}

	@Test
	public void askToVerifyTamperedDocument() throws SignatureUtilException, SignatureException, InvalidKeyException {
		buildEffectiveSut();
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		assertFalse(sut.verifySign(testDocument.substring(0, testDocument.length() - 5), sut.getDocumentSignature()));
	}

	/**
	 * Build SignatureUtil for tests
	 *
	 * @throws SignatureUtilException
	 */
	private void buildEffectiveSut() throws SignatureUtilException {
		try {
			sut = new SignatureUtilImpl(keyStorePath, "rcpxrcpx".getBytes());
		} catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

}
