package org.bverify;

import java.io.File;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

import client.Request;
import crpyto.CryptographicDigest;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import server.BVerifyServer;
import server.BVerifyServerRequestVerifier;
import server.StartingData;

public class SubmitUpdateBenchmarks {
	/**
	 * TEST PARAMATERS
	 */
	// mock data - setup with 10^6 entries
	public static final File MOCK_DATA_FILE = new File(System.getProperty("user.dir") + "/test-data");
	
	@State(Scope.Thread)
	public static class BenchmarkState {

		public BVerifyServer server;
		public Request request;
		public BVerifyServerRequestVerifier handler;
		public byte[] adsIdToUpdate;

		@Setup(Level.Trial)
		public void doSetup() {
			StartingData data = StartingData.loadFromFile(MOCK_DATA_FILE);
			this.server = new BVerifyServer(data, 2, false);
			this.handler = server.getRequestHandler();
		
			// now do a bunch of updates
			this.request = new Request(data);
			
			// we get the proof for this ADS
			List<byte[]> adsIds = request.getADSIds();
			this.adsIdToUpdate = adsIds.get(0);
		}

		@TearDown(Level.Invocation)
		public void doTearDown() {
			this.server.shutdown();
		}
	}
		
	@Benchmark @BenchmarkMode(Mode.SingleShotTime) @OutputTimeUnit(TimeUnit.MILLISECONDS)
	public void testSubmitUpdate(BenchmarkState s, Blackhole bh) {
		PerformUpdateRequest updateRequest = s.request.createPerformUpdateRequest(s.adsIdToUpdate, 
				CryptographicDigest.hash("NEW VALUE".getBytes()), 1, true);
		byte[] response = s.handler.performUpdate(updateRequest.toByteArray());
		// request should be accepted
		boolean accepted = Request.parsePerformUpdateResponse(response);
		if(!accepted) {
			throw new RuntimeException("something went wrong");
		}
		bh.consume(accepted);
	}
}
