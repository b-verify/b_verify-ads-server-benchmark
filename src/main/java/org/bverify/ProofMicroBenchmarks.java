package org.bverify;

import java.io.File;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Random;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

import client.Request;
import crpyto.CryptographicDigest;
import mpt.core.Utils;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootRequest;
import serialization.generated.BVerifyAPIMessageSerialization.ProveADSRootResponse;
import server.BVerifyServer;
import server.BVerifyServerRequestVerifier;
import server.StartingData;

public class ProofMicroBenchmarks {
	/**
	 * TEST PARAMATERS
	 */
	// mock data - setup with 10^6 entries
	public static final File MOCK_DATA_FILE = new File(System.getProperty("user.dir") + "/test-data");
	public static final int BATCH_SIZE = 1000;
	public static final int NUMBER_OF_UPDATE_BATCHES = 10;
	
	@State(Scope.Thread)
	public static class BenchmarkState {

		public BVerifyServer server;
		
		// proof production microbenchmarks
		public BVerifyServerRequestVerifier handler;
		public byte[] adsIdToRequestProofFor;	
		
		// proof verification microbenchmarks
		public byte[] adsIdToCheckProofFor;
		public ProveADSRootResponse proofToCheck;
		// to use in checking the proof
		public List<byte[]> commitments;
		public Request request;
		
		
		

		@Setup(Level.Trial)
		public void doSetup() {
			StartingData data = StartingData.loadFromFile(MOCK_DATA_FILE);
			this.server = new BVerifyServer(data, BATCH_SIZE, false);
			this.handler = server.getRequestHandler();
		
			// now do a bunch of updates
			this.request = new Request(data);
			
			// we get the proof for this ADS
			List<byte[]> adsIds = request.getADSIds();
			this.adsIdToRequestProofFor = adsIds.get(0);
			
			// we check the proof for this ADS
			this.adsIdToCheckProofFor = adsIds.get(1);
			
			// do a bunch of (deterministic) updates
			Random prng = new Random(924681);
			
			for(int batch = 1; batch <= NUMBER_OF_UPDATE_BATCHES; batch++) {
				System.out.println("commiting batch #"+batch+" of "+NUMBER_OF_UPDATE_BATCHES+
						" (batch size: "+BATCH_SIZE+")");
				for(int update = 1; update <= BATCH_SIZE; update++) {
					PerformUpdateRequest updateRequest = null;
					// first update is to the ads we will check the proof for
					if(update == 1 && batch == 1) {
						updateRequest = request.createPerformUpdateRequest(this.adsIdToCheckProofFor, 
								CryptographicDigest.hash("test".getBytes()), 
								batch, true);
						System.out.println("special update request: "+updateRequest);
					}else {
						// other updates are to random adses
						// select a random ADS to update
						int adsToUpdate = prng.nextInt(adsIds.size()-2)+2;
						byte[] adsIdToUpdate = adsIds.get(adsToUpdate);
						byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
						// create the update request
						updateRequest = request.createPerformUpdateRequest(adsIdToUpdate, newValue, 
								batch, false);
					}
					byte[] response = this.handler.performUpdate(updateRequest.toByteArray());
					
					// request should be accepted
					boolean accepted = Request.parsePerformUpdateResponse(response);
					if(!accepted) {
						throw new RuntimeException("something went wrong");
					}
				}
				try {
					// wait until the server commits
					while(this.handler.commitments().size() != batch+1) {
						Thread.sleep(10);
					}
				}catch (Exception e) {
					e.printStackTrace();
				}
			}
			System.out.println("all batches committed, commmitments: ");
			try {
				this.commitments = server.getRequestHandler().commitments();
				for(int i = 0; i < commitments.size(); i++) {
					System.out.println("#"+i+" - "+Utils.byteArrayAsHexString(this.commitments.get(i)));
				}
			}catch(RemoteException e) {
				throw new RuntimeException(e.getMessage());
			}
			System.out.println("getting proof for verifiaction benchmark: ");
			try {
				ProveADSRootRequest proveRequest = Request.createProveADSRootRequest(this.adsIdToCheckProofFor);
				byte[] response = this.handler.proveADSRoot(proveRequest.toByteArray());
				this.proofToCheck = Request.parseProveADSResponse(response);
				System.out.println("proof to check: "+this.proofToCheck);
			}catch(Exception e) {
				throw new RuntimeException(e.getMessage());
			}
			
		}

		@TearDown(Level.Trial)
		public void doTearDown() {
			this.server.shutdown();
		}
	}
		
	@Benchmark
	public void testFullProofGeneration(BenchmarkState s, Blackhole bh) {
		bh.consume(s.handler.proveADSRootMICROBENCHMARK(s.adsIdToRequestProofFor));
	}
	
	@Benchmark
	public void testProofUpdatesGeneration(BenchmarkState s, Blackhole bh) {
		bh.consume(s.handler.getProofUpdatesMICROBENCHMARK(s.adsIdToRequestProofFor));
	}
	
	@Benchmark
	public void testProofVerficationTime(BenchmarkState s, Blackhole bh) {
		bh.consume(s.handler.checkProofMICROBENCHAMRK(s.proofToCheck, s.request, s.adsIdToCheckProofFor, s.commitments));
	}
	
	@Benchmark
	public void testSubmitUpdate(BenchmarkState s, Blackhole bh) {
		PerformUpdateRequest updateRequest = s.request.createPerformUpdateRequest(s.adsIdToCheckProofFor, 
				CryptographicDigest.hash("NEW VALUE".getBytes()), 
				NUMBER_OF_UPDATE_BATCHES+1, true);
		byte[] response = s.handler.performUpdate(updateRequest.toByteArray());
		// request should be accepted
		boolean accepted = Request.parsePerformUpdateResponse(response);
		if(!accepted) {
			throw new RuntimeException("something went wrong");
		}
		bh.consume(accepted);
	}

}
