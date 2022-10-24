/*-
 * ========================LICENSE_START=================================
 * snp-attestd
 * %%
 * Copyright (C) 2022 Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */
package snp_attestd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	ar "github.com/industrial-data-space/idscp2-rat-drivers/idscp2-ra-snp/snp-attestd/attestation_report"

	"golang.org/x/sys/unix"
)

// This struct wraps a file descriptor for a SEV-SNP guest device.
// Guest ioctls can be executed using methods on this type.
type SnpDevice struct {
	file *os.File
}

// Opens the SEV-SNP guest device at the specified path.
// The device is usually found at /dev/sev-guest.
func OpenSnpDevice(path string) (*SnpDevice, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open SEV device: %w", err)
	}

	return &SnpDevice{file}, nil
}

type guestRequestIoctl struct {
	version  uint8
	reqData  uint64
	respData uint64
	fwError  uint64
}

const guestRequestIoctlSize = unsafe.Sizeof(guestRequestIoctl{})

type reportReq struct {
	userData [64]uint8
	vmpl     uint32
	reserved [28]uint8
}

const reportReqSize = unsafe.Sizeof(reportReq{})

// MSG_REPORT_RESP message from
// https://www.amd.com/system/files/TechDocs/56860.pdf, Table 23
type reportResp struct {
	Status     uint32
	ReportSize uint32
	Reserved   [24]byte
	Report     ar.AttestationReport
}

const reportRespSize = unsafe.Sizeof(reportResp{})

// The ioctl index has been obtained using this C function:
//
// #include <stdio.h>
// #include <linux/ioctl.h>
// #include <linux/sev-guest.h>
// int main() {
//     printf("%x\n", SNP_GET_REPORT);
// }
const snpGetReportIoctl = 0xc0205300

// Obtain an attestation report from the SEV firmware containing the specified reportData.
// This function wraps the SNP_GET_REPORT IOCTL on the SEV-SNP guest device.
func (dev *SnpDevice) GetReport(reportData []byte) (ar.AttestationReport, error) {
	if len(reportData) > 64 {
		return ar.AttestationReport{}, fmt.Errorf("expected up to 64 bytes of report data. Got %d bytes", len(reportData))
	}

	// Allocate a chunk of memory from the heap in order to store values related to the ioctl.
	// Since all values are stored in the same chunk, the go garbage collector should collect
	// them all at once.
	// The current garbage collector does not move objects on the heap, I believe.
	memory := make([]byte, guestRequestIoctlSize+reportReqSize+reportRespSize)
	memoryAddress := uintptr(unsafe.Pointer(&memory[0]))

	// Here comes the somewhat risky part...
	// Go technically forbids storing pointers to go memory in structures passed to C.
	// I think that this refers to pointers referring to garbage collected structs, as the go
	// runtime might free them while they are still used by C code.
	// Since we only point to the same memory block, we should be fine.
	// Also, if go decides to implement a compacting garbage collector in the future, the runtime
	// may decide to move the memory slice between us assigning the addresses here and calling the
	// ioctl later.
	ioctl := guestRequestIoctl{
		version:  1,
		reqData:  uint64(memoryAddress + guestRequestIoctlSize),
		respData: uint64(memoryAddress + guestRequestIoctlSize + reportReqSize),
	}

	// Copy the ioctl struct into the memory buffer.
	// We don't have to do any encoding here, as the go struct currently has the same layout
	// as its C counterpart.
	// It would probably be better to properly encode the data in the future.
	copy(memory, unsafe.Slice((*byte)(unsafe.Pointer(&ioctl)), guestRequestIoctlSize))

	req := reportReq{}
	copy(req.userData[:], reportData)

	copy(memory[guestRequestIoctlSize:], unsafe.Slice((*byte)(unsafe.Pointer(&req)), reportReqSize))

	// Pass the address of our memory object to the ioctl
	if err := unix.IoctlSetInt(int(dev.file.Fd()), snpGetReportIoctl, int(memoryAddress)); err != nil {
		return ar.AttestationReport{}, fmt.Errorf("error issuing ioctl on snp device: %w", err)
	}

	// Copy back the ioctl structure as the firmware response code is now set.
	// Note: fwError checking is currently disabled as the firmware seems to set this to an invalid value.
	//copy(unsafe.Slice((*byte)(unsafe.Pointer(&ioctl)), guestRequestIoctlSize), memory)
	//if ioctl.fwError != 0 {
	//	return AttestationReport{}, fmt.Errorf("The SEV firmware returned a non-zero error code: %x", ioctl.fwError)
	//}

	// Copy the response over from the memory buffer.
	// Since the response comes straight from the firmware, it is packed data.
	// The data fits in memory, as the packed data is at maximum the same size as reportResp.
	var resp reportResp
	if err := binary.Read(bytes.NewReader(memory[guestRequestIoctlSize+reportReqSize:]), binary.LittleEndian, &resp); err != nil {
		return ar.AttestationReport{}, fmt.Errorf("could not decode the attestation report from the firmware response: %w", err)
	}

	if resp.Status != 0 {
		return ar.AttestationReport{}, fmt.Errorf("the attestation response contains a non-zero status code: %x", resp.Status)
	}

	return resp.Report, nil
}
