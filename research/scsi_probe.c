// Read-only qualification of Apple's SCSITask transport. No F0/F2 implementation.
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/scsi/SCSITaskLib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr,"usage: scsi-probe IOREGISTRY_ENTRY_ID\n"); return 2; }
    uint64_t entry = strtoull(argv[1], NULL, 0);
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IORegistryEntryIDMatching(entry));
    if (!service) return 3;
    IOCFPlugInInterface **plugin = NULL;
    SInt32 score = 0;
    IOReturn result = IOCreatePlugInInterfaceForService(service, kIOSCSITaskDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
    IOObjectRelease(service);
    fprintf(stderr,"plugin: 0x%x\n",result);
    if (result || !plugin) return 4;
    SCSITaskDeviceInterface **device = NULL;
    HRESULT query = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOSCSITaskDeviceInterfaceID), (LPVOID *)&device);
    IODestroyPlugInInterface(plugin);
    if (query || !device) { fprintf(stderr,"query: 0x%x\n",(unsigned)query); return 5; }
    result = (*device)->ObtainExclusiveAccess(device);
    fprintf(stderr,"exclusive: 0x%x\n",result);
    if (result) { (*device)->Release(device); return 6; }
    SCSITaskInterface **task = (*device)->CreateSCSITask(device);
    if (!task) { (*device)->ReleaseExclusiveAccess(device); (*device)->Release(device); return 7; }
    UInt8 cdb[10] = {0xf1};
    UInt8 bytes[20] = {0};
    SCSITaskSGElement sg = { .address = (mach_vm_address_t)bytes, .length = sizeof(bytes) };
    result = (*task)->SetCommandDescriptorBlock(task,cdb,sizeof(cdb));
    if (!result) result=(*task)->SetScatterGatherEntries(task,&sg,1,sizeof(bytes),kSCSIDataTransfer_FromTargetToInitiator);
    if (!result) result=(*task)->SetTimeoutDuration(task,5000);
    SCSI_Sense_Data sense = {0}; SCSITaskStatus status = 0xff; UInt64 actual = 0;
    if (!result) result=(*task)->ExecuteTaskSync(task,&sense,&status,&actual);
    fprintf(stderr,"F1 transport=0x%x status=0x%x actual=%llu\n",result,status,actual);
    for (size_t i=0;i<sizeof(bytes);i++) printf("%02x",bytes[i]); puts("");
    (*task)->Release(task);
    IOReturn release=(*device)->ReleaseExclusiveAccess(device);
    (*device)->Release(device);
    fprintf(stderr,"release: 0x%x\n",release);
    return result || status || actual!=20 || release ? 8 : 0;
}
