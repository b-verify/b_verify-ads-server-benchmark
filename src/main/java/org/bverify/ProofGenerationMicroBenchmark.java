/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.bverify;

import java.io.File;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

import client.Request;
import crpyto.CryptographicDigest;
import crpyto.CryptographicSignature;
import mpt.core.Utils;
import serialization.generated.BVerifyAPIMessageSerialization.PerformUpdateRequest;
import server.BVerifyServer;
import server.BVerifyServerRequestVerifier;
import server.StartingData;

public class ProofGenerationMicroBenchmark {

	@State(Scope.Benchmark)
	public static class BenchmarkState {

		public BVerifyServerRequestVerifier handler;
		public BVerifyServer server;
		public byte[] adsIdToRequestProofFor;
		
		public byte[] witness;
		public List<byte[]> signatures;
		public List<PublicKey> signers;

		@Setup(Level.Trial)
		public void doSetup() {
			// test parameters
			// update 10 % of entries (100k)
			// in 10 batches of 1% (10k each)
			int batchSize = 10000;
			int nUpdateBatches = 10;
			
			File dataf = new File(System.getProperty("user.dir") + "/benchmarks/proof-throughput/test-data");
			StartingData data = StartingData.loadFromFile(dataf);
			this.server = new BVerifyServer(data, batchSize, false);
			this.handler = server.getRequestHandler();
		
			// now do a bunch of updates
			Request request = new Request(data);
			
			// we check the proof for this 
			List<byte[]> adsIds = request.getADSIds();
			this.adsIdToRequestProofFor = adsIds.get(0);
			
			// do a bunch of updates
			Random prng = new Random(924681);
			
			for(int batch = 1; batch <= nUpdateBatches; batch++) {
				System.out.println("commiting batch #"+batch+" of "+nUpdateBatches+" (batch size: "+batchSize+")");
				for(int update = 1; update <= batchSize; update++) {
					// select a random ADS to update
					int adsToUpdate = prng.nextInt(adsIds.size()-1)+1;
					byte[] adsIdToUpdate = adsIds.get(adsToUpdate);
					byte[] newValue =  CryptographicDigest.hash(("NEW VALUE"+update).getBytes());
					// create the update request
					PerformUpdateRequest updateRequest = request.createPerformUpdateRequest(adsIdToUpdate, newValue, 
							batch, false);
					byte[] response = this.handler.performUpdate(updateRequest.toByteArray());
					
					// request should be accepted
					boolean accepted = Request.parsePerformUpdateResponse(response);
					if(!accepted) {
						throw new RuntimeException("something went wrong");
					}
				}
				try {
					// wait until commitment is added
					while(this.handler.commitments().size() != batch+1) {
						Thread.sleep(10);
					}
				}catch (Exception e) {
					e.printStackTrace();
				}
			}
			System.out.println("all batches committed, commmitments: ");
			try {
				List<byte[]> commitments = server.getRequestHandler().commitments();
				for(int i = 0; i < commitments.size(); i++) {
					System.out.println("#"+i+" - "+Utils.byteArrayAsHexString(commitments.get(i)));
				}
			}catch(RemoteException e) {
				throw new RuntimeException(e.getMessage());
			}
			
			// now creating an update to sign, for testing time to verify signature
			PerformUpdateRequest updateRequest = request.createPerformUpdateRequest(this.adsIdToRequestProofFor, 
					CryptographicDigest.hash(("NEW VALUE").getBytes()), 1, true);
			System.out.println("update: "+updateRequest);
			this.signers = request.getAccountsThatMustSign(
					Arrays.asList(Map.entry(this.adsIdToRequestProofFor, 
							CryptographicDigest.hash(("NEW VALUE").getBytes()))))
					.stream().map(x -> x.getPublicKey()).collect(Collectors.toList());
			this.signatures = updateRequest.getSignaturesList().stream().map(x -> x.toByteArray()).collect(Collectors.toList());
			System.out.println("# of signatures: "+this.signers.size());
			assert this.signatures.size() == this.signers.size();
		}

		@TearDown(Level.Trial)
		public void doTearDown() {
			this.server.shutdown();
		}
	}
	
	@Benchmark
	public void testSignatureVerification(BenchmarkState s, Blackhole bh) {
		for(int i = 0; i < s.signatures.size(); i++) {
			bh.consume(CryptographicSignature.verify(s.witness, s.signatures.get(i), s.signers.get(i)));
		}
	}

	@Benchmark
	public void testProofGeneration(BenchmarkState s, Blackhole bh) {
		bh.consume(s.handler.proveADSRootMICROBENCHMARK(s.adsIdToRequestProofFor));
	}

}
