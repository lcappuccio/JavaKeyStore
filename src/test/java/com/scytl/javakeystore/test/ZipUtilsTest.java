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

	private final static String TEST_FILE = Main.OUTPUT_PATH + "output.zip";
	private ZipUtils sut;

	@Before
	public void setUp() throws IOException {
		File zipOutput = new File(TEST_FILE);
		zipOutput.delete();
		sut = new ZipUtils();
	}

	@After
	public void tearDown() throws IOException {
		File zipOutput = new File(TEST_FILE);
		zipOutput.delete();
		sut.closeZip();
	}

	@Test
	public void add_file_to_zip() throws IOException, URISyntaxException {
		sut = new ZipUtils();
		URL keyStoreURL = ClassLoader.getSystemResource("lorem_ipsum.txt");
		File keyStoreFile = new File(keyStoreURL.toURI());
		sut.addFileToZip(keyStoreFile);
		assert(new File(TEST_FILE).exists());
	}

}