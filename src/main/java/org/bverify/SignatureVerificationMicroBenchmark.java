package org.bverify;

import java.io.File;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

import client.Request;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import server.StartingData;

public class SignatureVerificationMicroBenchmark {
	
	public static final File MOCK_DATA_FILE = new File(System.getProperty("user.dir") + "/test-data");

	@State(Scope.Thread)
	public static class BenchmarkState {
		public byte[] witness;
		public List<byte[]> signatures;
		public List<PublicKey> signers;
		
		@Setup(Level.Trial)
		public void doSetup() {
			StartingData data = StartingData.loadFromFile(MOCK_DATA_FILE);
			Request request = new Request(data);
			byte[] adsId = request.getADSIds().get(0);
			
			// now creating an update to sign, for testing time to verify signature
			PerformUpdateRequest updateRequest = request.createPerformUpdateRequest(adsId, 
					CryptographicDigest.hash(("NEW VALUE").getBytes()), 1, true);
			System.out.println("update: "+updateRequest);
			this.signers = request.getAccountsThatMustSign(
					Arrays.asList(Map.entry(adsId, 
							CryptographicDigest.hash(("NEW VALUE").getBytes()))))
					.stream().map(x -> x.getPublicKey()).collect(Collectors.toList());
			this.witness = CryptographicDigest.hash(updateRequest.getUpdate().toByteArray());
			this.signatures = updateRequest.getSignaturesList().stream().map(x -> x.toByteArray()).collect(Collectors.toList());
			System.out.println("# of signers: "+this.signers.size()+" ("+this.signers+")");
			System.out.println("# of signatures : "+this.signatures.size()+" ("+this.signatures+")");
			assert this.signatures.size() == this.signers.size();
		}
		
	}
	
	@Benchmark
	public void testSignatureVerification(BenchmarkState s, Blackhole bh) {
		for(int i = 0; i < s.signatures.size(); i++) {
			bh.consume(CryptographicSignature.verify(s.witness, s.signatures.get(i), s.signers.get(i)));
		}
	}
	
}
