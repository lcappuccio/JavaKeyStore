/**
 *
 * @author leo
 * @date 10/04/2015 22:42
 *
 */
package com.scytl.javakeystore.api;

import com.scytl.javakeystore.exception.SignatureUtilException;

public interface SignatureUtil {

	/**
	 *
	 * @param keyAlias
	 * @param keyPasswd
	 * @throws SignatureUtilException
	 */
	public void useKey(String keyAlias, char[] keyPasswd) throws SignatureUtilException;

	/**
	 *
	 * @param document
	 * @throws SignatureUtilException
	 */
	public void signDocument(String document) throws SignatureUtilException;

	/**
	 *
	 * @param document
	 * @param documentSignature
	 * @return
	 * @throws SignatureUtilException
	 */
	public Boolean verifySign(String document, byte[] documentSignature) throws SignatureUtilException;

}
