/*
 * Copyright 2021 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client;

import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.gateway.CommitStatusResponse;
import org.hyperledger.fabric.protos.gateway.GatewayGrpc;
import org.hyperledger.fabric.protos.gateway.SignedCommitStatusRequest;
import org.hyperledger.fabric.protos.peer.TransactionPackage;

class CommitImpl implements Commit {
    private final GatewayGrpc.GatewayBlockingStub client;
    private final SigningIdentity signingIdentity;
    private final String transactionId;
    private SignedCommitStatusRequest signedRequest;
    private CommitStatusResponse response;

    CommitImpl(final GatewayGrpc.GatewayBlockingStub client, final SigningIdentity signingIdentity,
                final String transactionId, final SignedCommitStatusRequest signedRequest) {
        this.client = client;
        this.signingIdentity = signingIdentity;
        this.transactionId = transactionId;
        this.signedRequest = signedRequest;
    }

    @Override
    public byte[] getBytes() {
        return signedRequest.toByteArray();
    }

    @Override
    public byte[] getDigest() {
        byte[] message = signedRequest.getRequest().toByteArray();
        return signingIdentity.hash(message);
    }

    @Override
    public TransactionPackage.TxValidationCode getStatus() {
        return getCommitStatus().getResult();
    }

    @Override
    public boolean isSuccessful() {
        return getStatus() == TransactionPackage.TxValidationCode.VALID;
    }

    @Override
    public String getTransactionId() {
        return this.transactionId;
    }

    @Override
    public long getBlockNumber() {
        return getCommitStatus().getBlockNumber();
    }

    void setSignature(final byte[] signature) {
        signedRequest = signedRequest.toBuilder()
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    private CommitStatusResponse getCommitStatus() {
        if (null == response) {
            sign();
            response = client.commitStatus(signedRequest);
        }

        return response;
    }

    private void sign() {
        if (isSigned()) {
            return;
        }

        byte[] digest = getDigest();
        byte[] signature = signingIdentity.sign(digest);
        setSignature(signature);
    }

    private boolean isSigned() {
        return !signedRequest.getSignature().isEmpty();
    }
}
