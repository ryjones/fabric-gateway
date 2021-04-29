/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/gateway"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// Commit provides access to a committed transaction.
type Commit struct {
	client        gateway.GatewayClient
	signingID     *signingIdentity
	transactionID string
	signedRequest *gateway.SignedCommitStatusRequest
	status        peer.TxValidationCode
}

func newCommit(
	client gateway.GatewayClient,
	signingID *signingIdentity,
	transactionID string,
	signedRequest *gateway.SignedCommitStatusRequest,
) *Commit {
	return &Commit{
		client:        client,
		signingID:     signingID,
		transactionID: transactionID,
		signedRequest: signedRequest,
		status:        -1,
	}
}

// Bytes of the serialized commit.
func (commit *Commit) Bytes() ([]byte, error) {
	requestBytes, err := proto.Marshal(commit.signedRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshall SignedCommitStatusRequest protobuf: %w", err)
	}

	return requestBytes, nil
}

// Digest of the commit status request. This is used to generate a digital signature.
func (commit *Commit) Digest() []byte {
	return commit.signingID.Hash(commit.signedRequest.Request)
}

// Status of the committed transaction. If the transaction has not yet committed, this call blocks until the commit
// occurs.
func (commit *Commit) Status() (peer.TxValidationCode, error) {
	if commit.status < 0 {
		if err := commit.sign(); err != nil {
			return 0, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		status, err := commit.client.CommitStatus(ctx, commit.signedRequest)
		if err != nil {
			return 0, fmt.Errorf("failed to obtain transaction commit status: %w", err)
		}

		commit.status = status.Result
	}

	return commit.status, nil
}

// Successful returns true if the transaction committed successfully; otherwise false. If the transaction has not yet
// committed, this call blocks until the commit occurs.
func (commit *Commit) Successful() (bool, error) {
	status, err := commit.Status()
	if err != nil {
		return false, err
	}

	return status == peer.TxValidationCode_VALID, nil
}

// TransactionID of the transaction.
func (commit *Commit) TransactionID() string {
	return commit.transactionID
}

func (commit *Commit) sign() error {
	if commit.isSigned() {
		return nil
	}

	digest := commit.Digest()
	signature, err := commit.signingID.Sign(digest)
	if err != nil {
		return err
	}

	commit.setSignature(signature)

	return nil
}

func (commit *Commit) isSigned() bool {
	return len(commit.signedRequest.Signature) > 0
}

func (commit *Commit) setSignature(signature []byte) {
	commit.signedRequest.Signature = signature
}
