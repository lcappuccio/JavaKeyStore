package com.scytl.javakeystore.test;

import com.scytl.javakeystore.main.Main;
import com.scytl.javakeystore.pojo.ZipUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * @author leo
 * @date 26/12/15 13:11
 */
public class ZipUtilsTest {

	private ZipUtils sut;

	@Before
	public void setup() throws IOException {
		File zipOutput = new File(Main.OUTPUT_PATH + "output.zip");
		zipOutput.delete();
		sut = new ZipUtils();
	}

	@After
	public void tearDown() throws IOException {
		File zipOutput = new File(Main.OUTPUT_PATH + "output.zip");
		zipOutput.delete();
		sut.closeZip();
	}

	@Test
	public void add_file_to_zip() throws IOException, URISyntaxException {
		sut = new ZipUtils();
		URL keyStoreURL = ClassLoader.getSystemResource("lorem_ipsum.txt");
		File keyStoreFile = new File(keyStoreURL.toURI());
		sut.addFileToZip(keyStoreFile);

	}

}