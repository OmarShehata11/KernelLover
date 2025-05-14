#pragma once

// here we will define the IOCTL to be used for user mode

#define HV_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8ccc, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
