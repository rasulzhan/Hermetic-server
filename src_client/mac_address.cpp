#include "mac_address.h"

#include <iostream>
#include <string>
#include <fstream>
#ifdef _WIN32
# include <iphlpapi.h>
# include <Windows.h>
# pragma comment(lib, "iphlpapi.lib")
#else
# include <net/if.h>
# include <sys/ioctl.h>
# include <unistd.h>
#endif

std::string
getMacAddress()
{
#if _WIN32
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD           adapterInfoSize = sizeof(adapterInfo);
    DWORD           result = GetAdaptersInfo(adapterInfo, &adapterInfoSize);
    if (result != ERROR_SUCCESS) {
        return "";
    }

    std::string      macAddress;
    PIP_ADAPTER_INFO adapter = adapterInfo;
    while (adapter) {
        if (adapter->Type == MIB_IF_TYPE_ETHERNET && adapter->AddressLength == 6) {
            char buffer[18];
            snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", adapter->Address[0],
                     adapter->Address[1], adapter->Address[2], adapter->Address[3],
                     adapter->Address[4], adapter->Address[5]);
            macAddress = buffer;
            break;
        }
        adapter = adapter->Next;
    }
    return macAddress;
#else

        std::ifstream file(
            "/sys/class/net/eth0/address");  // Change "eth0" to your desired network interface
        if (!file) {
            return "";
        }

        std::string macAddress;
        getline(file, macAddress);
        file.close();
        return macAddress;

#endif
}
