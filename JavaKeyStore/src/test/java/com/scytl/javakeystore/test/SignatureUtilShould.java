/**
 * $Id$
 *
 * @author lcappuccio
 * @date 09/04/2015 10:42
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.test;

import com.scytl.javakeystore.exception.SignatureUtilException;
import com.scytl.javakeystore.pojo.SignatureUtil;
import java.util.Arrays;
import org.junit.Test;

public class SignatureUtilShould {

	SignatureUtil sut;

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void throwExceptionNotExistingFile() throws SignatureUtilException {
		sut = new SignatureUtil("abc", "somepassword".getBytes());
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void wrongKeyStorePasswordException() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "abc".getBytes());
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void nonExistingKeyAliasDisplaysError() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "some_missing_key_alias";
		char[] keyPasswd = "some_nonexisting_pwd".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
	}

	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void askToSignNullDocumentThrowsException() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
		// Sign the document with the preselected key
		sut.signDocument(null);
	}
	
	@Test(expected = com.scytl.javakeystore.exception.SignatureUtilException.class)
	public void throwExceptionOnBadSignature() throws SignatureUtilException {
		sut = new SignatureUtil("src/test/resources/client.jks", "rcpxrcpx".getBytes());
		// Select private key
		String keyAlias = "client";
		char[] keyPasswd = "rcpx".toCharArray();
		sut.useKey(keyAlias, keyPasswd);
		// Sign the document with the preselected key
		String testDocument = "some text document";
		sut.signDocument(testDocument);
		// Tamper the signature
		byte[] testSignature = sut.getDocumentSignature();
		sut.verifySign(testDocument, Arrays.copyOf(testSignature, testSignature.length - 5));
	}

}
