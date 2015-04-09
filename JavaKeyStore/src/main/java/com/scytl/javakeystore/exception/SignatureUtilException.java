/**
 * $Id$
 *
 * @author lcappuccio
 * @date 09/04/2015 11:00
 *
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 *
 * All rights reserved.
 *
 */
package com.scytl.javakeystore.exception;

public class SignatureUtilException extends Exception {
	
	private static final long serialVersionUID = 5495464303671968900L;
	
    /**
     * Constructs an instance of <code>SecurityException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public SignatureUtilException(String msg) {
        super(msg);
    }
}
