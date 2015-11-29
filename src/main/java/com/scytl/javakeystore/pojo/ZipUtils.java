/**
 * $Id$
 *
 * @author lcappuccio
 * @date 08/04/2015 16:11
 * <p>
 * Copyright (C) 2015 Scytl Secure Electronic Voting SA
 * <p>
 * All rights reserved.
 */
package com.scytl.javakeystore.pojo;

import com.scytl.javakeystore.main.Main;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZipUtils {

	private final ZipOutputStream zipOutput;
	private final byte[] buffer;

	public ZipUtils() throws IOException {
		this.buffer = new byte[1024];
		FileOutputStream fos = new FileOutputStream(Main.OUTPUT_PATH + "output" + ".zip");
		zipOutput = new ZipOutputStream(fos);
		fos.close();
	}

	/**
	 *
	 * @param fileName the file to be added to the zip
	 * @throws IOException
	 */
	public void addFileToZip(File fileName) throws IOException {
		ZipEntry zipEntry = new ZipEntry(fileName.getName());
		zipOutput.putNextEntry(zipEntry);
		try (FileInputStream in = new FileInputStream(fileName)) {
			int len;
			while ((len = in.read(buffer)) > 0) {
				zipOutput.write(buffer, 0, len);
			}
		}
		zipOutput.closeEntry();
	}

	/**
	 *
	 * @throws IOException
	 */
	public void closeZip() throws IOException {
		// close it
		zipOutput.close();
	}
}
