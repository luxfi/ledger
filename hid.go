//go:build !ledger_mock && !ledger_zemu
// +build !ledger_mock,!ledger_zemu

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// HID implementation adapted from github.com/zondax/ledger-go
// Licensed under the Apache License, Version 2.0

package ledger

import (
	"errors"
	"sync"
	"time"

	"github.com/luxfi/hid"
)

const (
	VendorLedger         = 0x2c97
	UsagePageLedgerNanoS = 0xffa0
	Channel              = 0x0101
	PacketSize           = 64
)

// LedgerAdmin defines the interface for managing Ledger devices.
type LedgerAdmin interface {
	CountDevices() int
	ListDevices() ([]string, error)
	Connect(deviceIndex int) (LedgerDevice, error)
}

// LedgerDevice defines the interface for interacting with a Ledger device.
type LedgerDevice interface {
	Exchange(command []byte) ([]byte, error)
	Close() error
}

type LedgerAdminHID struct{}

type LedgerDeviceHID struct {
	device      *hid.Device
	readCo      *sync.Once
	readChannel chan []byte
}

// list of supported product ids as well as their corresponding interfaces
var supportedLedgerProductID = map[uint8]int{
	0x40: 0, // Ledger Nano X
	0x10: 0, // Ledger Nano S
	0x50: 0, // Ledger Nano S Plus
	0x60: 0, // Ledger Stax
	0x70: 0, // Ledger Flex
}

func NewLedgerAdmin() LedgerAdmin {
	return &LedgerAdminHID{}
}

func (admin *LedgerAdminHID) ListDevices() ([]string, error) {
	devices := hid.Enumerate(0, 0)
	if len(devices) == 0 {
		log.Debug("No devices. Ledger LOCKED OR Other Program/Web Browser may have control of device.")
	}

	for _, d := range devices {
		logDeviceInfo(d)
	}

	return []string{}, nil
}

func logDeviceInfo(d hid.DeviceInfo) {
	log.Debugf("============ %s", d.Path)
	log.Debugf("VendorID      : %x", d.VendorID)
	log.Debugf("ProductID     : %x", d.ProductID)
	log.Debugf("Release       : %x", d.Release)
	log.Debugf("Serial        : %x", d.Serial)
	log.Debugf("Manufacturer  : %s", d.Manufacturer)
	log.Debugf("Product       : %s", d.Product)
	log.Debugf("UsagePage     : %x", d.UsagePage)
	log.Debugf("Usage         : %x", d.Usage)
}

func isLedgerDevice(d hid.DeviceInfo) bool {
	deviceFound := d.UsagePage == UsagePageLedgerNanoS

	productIDMM := uint8(d.ProductID >> 8)
	if interfaceID, supported := supportedLedgerProductID[productIDMM]; deviceFound || (supported && (interfaceID == d.Interface)) {
		return true
	}

	return false
}

func (admin *LedgerAdminHID) CountDevices() int {
	devices := hid.Enumerate(0, 0)

	count := 0
	for _, d := range devices {
		if d.VendorID == VendorLedger && isLedgerDevice(d) {
			count++
		}
	}

	return count
}

func (admin *LedgerAdminHID) Connect(deviceIndex int) (LedgerDevice, error) {
	devices := hid.Enumerate(0, 0)

	currentIndex := 0
	for _, d := range devices {
		if d.VendorID == VendorLedger && isLedgerDevice(d) {
			if currentIndex == deviceIndex {
				device, err := d.Open()
				if err != nil {
					return nil, err
				}
				return &LedgerDeviceHID{device: device, readCo: &sync.Once{}, readChannel: make(chan []byte)}, nil
			}
			currentIndex++
		}
	}

	return nil, errors.New("device not found")
}

func (ledger *LedgerDeviceHID) write(buffer []byte) (int, error) {
	totalBytes := len(buffer)
	totalWrittenBytes := 0
	for totalBytes > totalWrittenBytes {
		writtenBytes, err := ledger.device.Write(buffer)
		if err != nil {
			return totalWrittenBytes, err
		}
		totalWrittenBytes += writtenBytes
	}
	return totalWrittenBytes, nil
}

func (ledger *LedgerDeviceHID) Read() <-chan []byte {
	ledger.readCo.Do(func() {
		go ledger.readThread()
	})
	return ledger.readChannel
}

func (ledger *LedgerDeviceHID) readThread() {
	defer close(ledger.readChannel)
	for {
		buffer := make([]byte, PacketSize)
		readBytes, err := ledger.device.Read(buffer)
		if err != nil {
			return
		}
		select {
		case ledger.readChannel <- buffer[:readBytes]:
		default:
		}
	}
}

func (ledger *LedgerDeviceHID) Exchange(command []byte) ([]byte, error) {
	if len(command) < 5 {
		return nil, errors.New("APDU commands should not be smaller than 5")
	}

	log.Debugf("[HID] => %x", command)

	err := ledger.sendChunks(command)
	if err != nil {
		return nil, err
	}

	return ledger.getResponse()
}

func (ledger *LedgerDeviceHID) sendChunks(command []byte) error {
	chunks, err := WrapCommandAPDU(Channel, command, PacketSize)
	if err != nil {
		return err
	}
	for _, chunk := range chunks {
		_, err := ledger.write(chunk)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ledger *LedgerDeviceHID) getResponse() ([]byte, error) {
	readChannel := ledger.Read()

	var response []byte
	needMore := true
	for needMore {
		select {
		case buffer, ok := <-readChannel:
			if !ok {
				return nil, errors.New("read channel closed")
			}
			var responseChunk []byte
			responseChunk, needMore = UnwrapResponseAPDU(Channel, buffer, PacketSize)
			response = append(response, responseChunk...)
		case <-time.After(20 * time.Second):
			return nil, errors.New("timeout reading from device")
		}
	}

	log.Debugf("[HID] <= %x", response)

	if len(response) < 2 {
		return nil, errors.New("response too short")
	}

	return response, nil
}

func (ledger *LedgerDeviceHID) Close() error {
	return ledger.device.Close()
}
