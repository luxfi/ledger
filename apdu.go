// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// APDU wrapper adapted from github.com/zondax/ledger-go
// Licensed under the Apache License, Version 2.0

package ledger

import (
	"encoding/binary"
	"errors"
)

// WrapCommandAPDU turns the command into a sequence of 64 byte packets for HID transport
func WrapCommandAPDU(channel uint16, command []byte, packetSize int) ([][]byte, error) {
	if packetSize < 3 {
		return nil, errors.New("packet size must be at least 3")
	}

	var chunks [][]byte
	header := make([]byte, 5)
	binary.BigEndian.PutUint16(header[0:2], channel)
	header[2] = 0x05 // TAG_APDU
	binary.BigEndian.PutUint16(header[3:5], uint16(len(command)))

	// First packet includes total length
	firstPacket := make([]byte, packetSize)
	copy(firstPacket[0:5], header)

	remainingInFirst := packetSize - 5
	commandOffset := 0

	if len(command) <= remainingInFirst {
		copy(firstPacket[5:], command)
		chunks = append(chunks, firstPacket)
		return chunks, nil
	}

	copy(firstPacket[5:], command[:remainingInFirst])
	chunks = append(chunks, firstPacket)
	commandOffset = remainingInFirst

	// Subsequent packets
	seqNum := uint16(0)
	for commandOffset < len(command) {
		packet := make([]byte, packetSize)
		binary.BigEndian.PutUint16(packet[0:2], channel)
		packet[2] = 0x05 // TAG_APDU
		binary.BigEndian.PutUint16(packet[3:5], seqNum)
		seqNum++

		remaining := len(command) - commandOffset
		copyLen := packetSize - 5
		if remaining < copyLen {
			copyLen = remaining
		}
		copy(packet[5:], command[commandOffset:commandOffset+copyLen])
		commandOffset += copyLen
		chunks = append(chunks, packet)
	}

	return chunks, nil
}

// UnwrapResponseAPDU processes a packet from HID transport and returns the payload
func UnwrapResponseAPDU(channel uint16, packet []byte, packetSize int) ([]byte, bool) {
	if len(packet) < 5 {
		return nil, false
	}

	receivedChannel := binary.BigEndian.Uint16(packet[0:2])
	if receivedChannel != channel {
		return nil, false
	}

	if packet[2] != 0x05 { // TAG_APDU
		return nil, false
	}

	seqOrLen := binary.BigEndian.Uint16(packet[3:5])

	dataStart := 5
	dataEnd := len(packet)
	if dataEnd > packetSize {
		dataEnd = packetSize
	}

	data := packet[dataStart:dataEnd]

	// Trim trailing zeros (padding)
	lastNonZero := len(data)
	for lastNonZero > 0 && data[lastNonZero-1] == 0 {
		lastNonZero--
	}

	needMore := seqOrLen > 0 && len(data) > 0

	return data[:lastNonZero], needMore
}
