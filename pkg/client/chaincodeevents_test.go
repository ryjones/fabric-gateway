/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/gateway"
	"github.com/hyperledger/fabric-protos-go/peer"
)

//go:generate mockgen -destination ./chaincodeevents_mock_test.go -package ${GOPACKAGE} github.com/hyperledger/fabric-protos-go/gateway Gateway_ChaincodeEventsClient

func TestChaincodeEvents(t *testing.T) {
	newChaincodeEventsResponse := func(events []*ChaincodeEvent) *gateway.ChaincodeEventsResponse {
		blockNumber := uint64(0)
		var peerEvents []*peer.ChaincodeEvent

		for _, event := range events {
			blockNumber = event.BlockNumber
			peerEvents = append(peerEvents, &peer.ChaincodeEvent{
				ChaincodeId: event.ChaincodeID,
				TxId:        event.TransactionID,
				EventName:   event.EventName,
				Payload:     event.Payload,
			})
		}

		return &gateway.ChaincodeEventsResponse{
			BlockNumber: blockNumber,
			Events:      peerEvents,
		}
	}

	assertEqualEvents := func(t *testing.T, expected *ChaincodeEvent, actual *ChaincodeEvent) {
		if expected.BlockNumber != actual.BlockNumber ||
			expected.ChaincodeID != actual.ChaincodeID ||
			expected.EventName != actual.EventName ||
			expected.TransactionID != actual.TransactionID ||
			!bytes.Equal(expected.Payload, actual.Payload) {
			t.Fatalf("Events are not equal.\nExpected: %v\nGot: %v", expected, actual)
		}
	}

	t.Run("Returns error read on connect error", func(t *testing.T) {
		controller := gomock.NewController(t)
		mockClient := NewMockGatewayClient(controller)

		mockClient.EXPECT().ChaincodeEvents(gomock.Any(), gomock.Any()).
			Return(nil, errors.New("CONNECT_ERROR"))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		network := AssertNewTestNetwork(t, "NETWORK", WithClient(mockClient))
		_, err := network.ChaincodeEvents(ctx, "CHAINCODE_ID")

		if err == nil || !strings.Contains(err.Error(), "CONNECT_ERROR") {
			t.Fatalf("Expected connect error, got %v", err)
		}
	})

	t.Run("Sends valid request", func(t *testing.T) {
		controller := gomock.NewController(t)
		mockClient := NewMockGatewayClient(controller)
		mockEvents := NewMockGateway_ChaincodeEventsClient(controller)

		var actual *gateway.ChaincodeEventsRequest
		mockClient.EXPECT().ChaincodeEvents(gomock.Any(), gomock.Any()).
			Do(func(_ context.Context, in *gateway.SignedChaincodeEventsRequest) {
				request := &gateway.ChaincodeEventsRequest{}
				if err := proto.Unmarshal(in.GetRequest(), request); err != nil {
					t.Fatal(err)
				}
				actual = &gateway.ChaincodeEventsRequest{
					ChannelId:   request.ChannelId,
					ChaincodeId: request.ChaincodeId,
				}
			}).
			Return(mockEvents, nil).
			Times(1)

		mockEvents.EXPECT().Recv().
			Return(nil, errors.New("fake")).
			AnyTimes()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		network := AssertNewTestNetwork(t, "NETWORK", WithClient(mockClient))
		_, err := network.ChaincodeEvents(ctx, "CHAINCODE_ID")
		if err != nil {
			t.Fatal(err)
		}

		expected := &gateway.ChaincodeEventsRequest{
			ChannelId:   "NETWORK",
			ChaincodeId: "CHAINCODE_ID",
		}
		if !proto.Equal(expected, actual) {
			t.Fatalf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("Closes event channel on receive error", func(t *testing.T) {
		controller := gomock.NewController(t)
		mockClient := NewMockGatewayClient(controller)
		mockEvents := NewMockGateway_ChaincodeEventsClient(controller)

		mockClient.EXPECT().ChaincodeEvents(gomock.Any(), gomock.Any()).
			Return(mockEvents, nil)

		mockEvents.EXPECT().Recv().
			Return(nil, errors.New("fake")).
			AnyTimes()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		network := AssertNewTestNetwork(t, "NETWORK", WithClient(mockClient))
		receive, err := network.ChaincodeEvents(ctx, "CHAINCODE_ID")
		if err != nil {
			t.Fatal(err)
		}

		actual, ok := <-receive

		if ok {
			t.Fatalf("Expected event listening to be cancelled, got %v", actual)
		}
	})

	t.Run("Receives events", func(t *testing.T) {
		controller := gomock.NewController(t)
		mockClient := NewMockGatewayClient(controller)
		mockEvents := NewMockGateway_ChaincodeEventsClient(controller)

		mockClient.EXPECT().ChaincodeEvents(gomock.Any(), gomock.Any()).
			Return(mockEvents, nil)

		expected := []*ChaincodeEvent{
			{
				BlockNumber:   1,
				ChaincodeID:   "CHAINCODE_ID",
				EventName:     "EVENT_1",
				Payload:       []byte("PAYLOAD_1"),
				TransactionID: "TRANSACTION_ID_1",
			},
			{
				BlockNumber:   1,
				ChaincodeID:   "CHAINCODE_ID",
				EventName:     "EVENT_2",
				Payload:       []byte("PAYLOAD_2"),
				TransactionID: "TRANSACTION_ID_2",
			},
			{
				BlockNumber:   2,
				ChaincodeID:   "CHAINCODE_ID",
				EventName:     "EVENT_3",
				Payload:       []byte("PAYLOAD_3"),
				TransactionID: "TRANSACTION_ID_3",
			},
		}

		responses := []*gateway.ChaincodeEventsResponse{
			newChaincodeEventsResponse(expected[0:2]),
			newChaincodeEventsResponse(expected[2:]),
		}
		responseIndex := 0
		mockEvents.EXPECT().Recv().
			DoAndReturn(func() (*gateway.ChaincodeEventsResponse, error) {
				if responseIndex >= len(responses) {
					return nil, errors.New("fake")
				}
				response := responses[responseIndex]
				responseIndex++
				return response, nil
			}).
			AnyTimes()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		network := AssertNewTestNetwork(t, "NETWORK", WithClient(mockClient))
		receive, err := network.ChaincodeEvents(ctx, "CHAINCODE_ID")
		if err != nil {
			t.Fatal(err)
		}

		for _, event := range expected {
			actual := <-receive
			assertEqualEvents(t, event, actual)
		}
	})
}
