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

import com.scytl.javakeystore.pojo.Security;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.junit.Test;

public class KeyStoreShould {
	
	Security sut;
	
    @Test(expected = SecurityException.class)
	public void throwExceptionNotExistingFile() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {
		sut = new Security("abc", "somepassword".getBytes());
	}
	
	@Test(expected = SecurityException.class)
	public void wrongKeyStorePasswordException() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {
		sut = new Security("src/test/resources/client.jks", "abc".getBytes());
	}

}