// Thin ownership/IO bridge. Compatibility, protocol validation and update policy are Rust-owned.
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOUSBHost/IOUSBHost.h>
#import <IOKit/usb/USB.h>
#import <DiskArbitration/DiskArbitration.h>
#include <stdatomic.h>

// The pinned build SDK predates this public method. Match the current Apple
// header's NSUInteger ABI and require runtime support before any capture.
#if __MAC_OS_X_VERSION_MAX_ALLOWED < 260000
@interface IOUSBHostObject (GuSurrenderDeclaration)
- (void)destroyWithOptions:(NSUInteger)options;
@end
#endif

static NSDictionary *properties(io_registry_entry_t entry) {
    CFMutableDictionaryRef value = NULL;
    if (IORegistryEntryCreateCFProperties(entry, &value, kCFAllocatorDefault, 0)) return nil;
    return CFBridgingRelease(value);
}
static uint64_t entry_id(io_registry_entry_t entry) {
    uint64_t value = 0; IORegistryEntryGetRegistryEntryID(entry, &value); return value;
}
static uint64_t usb_ancestor(io_registry_entry_t entry) {
    IOObjectRetain(entry);
    while (entry) {
        if (IOObjectConformsTo(entry,"IOUSBHostDevice")) { uint64_t result=entry_id(entry); IOObjectRelease(entry); return result; }
        io_registry_entry_t parent=0;
        kern_return_t result=IORegistryEntryGetParentEntry(entry,kIOServicePlane,&parent);
        IOObjectRelease(entry); entry=result ? 0 : parent;
    }
    return 0;
}
static BOOL bot_profile(NSDictionary *p) {
    return [p[@"bInterfaceClass"] intValue]==8 && [p[@"bInterfaceSubClass"] intValue]==6 && [p[@"bInterfaceProtocol"] intValue]==0x50;
}
static NSMutableDictionary *candidate(uint64_t id) {
    return [@{@"ancestor":@(id),@"generation":@(id),@"main_access":@NO,@"bluetooth_access":@NO,@"observed_profile":@NO,@"conflicting_model":@NO,@"disks":[NSMutableArray new]} mutableCopy];
}
char *gu_snapshot(void) {
    @autoreleasepool {
        NSMutableDictionary<NSNumber *,NSMutableDictionary *> *devices=[NSMutableDictionary new];
        NSMutableArray *errors=[NSMutableArray new];
        io_iterator_t iterator=0;
        if (IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching("IOUSBHostDevice"),&iterator)) { [errors addObject:@"USB enumeration failed"]; }
        io_service_t service;
        while (iterator && (service=IOIteratorNext(iterator))) {
            NSDictionary *p=properties(service);
            if (!p) [errors addObject:@"USB properties unavailable"];
            io_iterator_t children=0; BOOL bot=NO;
            if (IORegistryEntryCreateIterator(service,kIOServicePlane,kIORegistryIterateRecursively,&children)) [errors addObject:@"USB child enumeration failed"];
            io_service_t child;
            while (children && (child=IOIteratorNext(children))) {
                if (IOObjectConformsTo(child,"IOUSBHostInterface")) {
                    NSDictionary *ip=properties(child);
                    if (!ip) [errors addObject:@"Interface properties unavailable"];
                    if (bot_profile(ip)) bot=YES;
                }
                IOObjectRelease(child);
            }
            if (children) IOObjectRelease(children);
            BOOL observed=[p[@"idVendor"] intValue]==0x34d3 && [p[@"idProduct"] intValue]==0x1100;
            BOOL recognized=observed || (bot && ([p[@"idVendor"] intValue]==0x34d3 || [[p[@"USB Vendor Name"] lowercaseString] containsString:@"gul"]));
            if (recognized) {
                uint64_t id=entry_id(service);
                if (!id) [errors addObject:@"USB attachment ID unavailable"];
                else { NSMutableDictionary *c=candidate(id);c[@"observed_profile"]=(observed && bot) ? @YES : @NO;c[@"bluetooth_access"]=bot ? @YES : @NO;devices[@(id)]=c; }
            }
            IOObjectRelease(service);
        }
        if (iterator) IOObjectRelease(iterator);
        DASessionRef session=DASessionCreate(kCFAllocatorDefault);
        if (!session) [errors addObject:@"Disk Arbitration unavailable"];
        iterator=0;
        if (IOServiceGetMatchingServices(kIOMainPortDefault,IOServiceMatching("IOMedia"),&iterator)) [errors addObject:@"Media enumeration failed"];
        while (iterator && (service=IOIteratorNext(iterator))) {
            NSDictionary *p=properties(service);
            NSString *bsd=p[@"BSD Name"];
            DADiskRef disk=session && bsd ? DADiskCreateFromBSDName(kCFAllocatorDefault,session,bsd.UTF8String) : NULL;
            NSDictionary *description=disk ? CFBridgingRelease(DADiskCopyDescription(disk)) : nil;
            NSString *label=description[(__bridge NSString *)kDADiskDescriptionVolumeNameKey];
            uint64_t id=usb_ancestor(service);
            BOOL recognized=[label caseInsensitiveCompare:@"GuliKit"]==NSOrderedSame && label!=nil;
            NSMutableDictionary *c=devices[@(id)];
            if (recognized && !id) [errors addObject:@"GuliKit volume has no physical USB ancestor"];
            if (recognized && id && !c) {c=candidate(id); devices[@(id)]=c;}
            if (c && bsd) {
                if (!description) [errors addObject:@"Candidate media description unavailable"];
                NSURL *url=description[(__bridge NSString *)kDADiskDescriptionVolumePathKey];
                [c[@"disks"] addObject:@{@"bsd":bsd,@"mount":url.path ?: @"",@"writable":[description[(__bridge NSString *)kDADiskDescriptionMediaWritableKey] boolValue] ? @YES : @NO}];
                if (url) {
                    if (c[@"mount"]) [errors addObject:@"Candidate has multiple mounted volumes"];
                    c[@"mount"]=url.path;c[@"main_access"]=@YES;
                }
            }
            if (disk) CFRelease(disk);
            IOObjectRelease(service);
        }
        if (iterator) IOObjectRelease(iterator);if (session) CFRelease(session);
        NSError *error=nil;
        NSData *json=[NSJSONSerialization dataWithJSONObject:@{@"candidates":devices.allValues,@"incomplete":errors} options:NSJSONWritingSortedKeys error:&error];
        return json ? strndup(json.bytes,json.length) : strdup("{\"candidates\":[],\"incomplete\":[\"serialization failed\"]}");
    }
}
void gu_free(void *value) { free(value); }

typedef struct { IONotificationPortRef port; dispatch_queue_t queue; io_iterator_t added,removed; atomic_uint_fast64_t epoch,arrivals; } GuWatch;
static void watch_event(void *context,io_iterator_t iterator) {
    GuWatch *watch=context;io_service_t entry;
    while ((entry=IOIteratorNext(iterator))) { atomic_fetch_add(&watch->epoch,1);if(iterator==watch->added)atomic_fetch_add(&watch->arrivals,1);IOObjectRelease(entry); }
}
void *gu_watch_open(void) {
    GuWatch *watch=calloc(1,sizeof(*watch));if (!watch) return NULL;
    atomic_init(&watch->epoch,0);
    atomic_init(&watch->arrivals,0);
    watch->port=IONotificationPortCreate(kIOMainPortDefault);
    if (!watch->port) {free(watch);return NULL;}
    watch->queue=dispatch_queue_create("lol.mjc.gulikit-usb-watch",DISPATCH_QUEUE_SERIAL);
    IONotificationPortSetDispatchQueue(watch->port,watch->queue);
    if (IOServiceAddMatchingNotification(watch->port,kIOFirstMatchNotification,IOServiceMatching("IOUSBHostDevice"),watch_event,watch,&watch->added) || IOServiceAddMatchingNotification(watch->port,kIOTerminatedNotification,IOServiceMatching("IOUSBHostDevice"),watch_event,watch,&watch->removed)) {
        IONotificationPortDestroy(watch->port);dispatch_sync(watch->queue,^{});if(watch->added)IOObjectRelease(watch->added);if(watch->removed)IOObjectRelease(watch->removed);watch->queue=nil;free(watch);return NULL;
    }
    dispatch_sync(watch->queue, ^{watch_event(watch,watch->added);watch_event(watch,watch->removed);});
    return watch;
}
uint64_t gu_watch_epoch(void *context) {GuWatch *watch=context;dispatch_sync(watch->queue,^{});return atomic_load(&watch->epoch);}
void gu_watch_state(void *context,uint64_t *epoch,uint64_t *arrivals) {GuWatch *watch=context;dispatch_sync(watch->queue,^{*epoch=atomic_load(&watch->epoch);*arrivals=atomic_load(&watch->arrivals);});}
void gu_watch_close(void *context) {
    GuWatch *watch=context;IONotificationPortSetDispatchQueue(watch->port,NULL);
    dispatch_sync(watch->queue,^{});IONotificationPortDestroy(watch->port);
    IOObjectRelease(watch->added);IOObjectRelease(watch->removed);watch->queue=nil;free(watch);
}

@interface GuTransport : NSObject
@property IOUSBHostDevice *device;
@property IOUSBHostInterface *interface;
@property IOUSBHostPipe *input;
@property IOUSBHostPipe *output;
@property uint8_t inputAddress;
@property uint8_t outputAddress;
@end
@implementation GuTransport
@end
static void error_text(char *buffer,size_t size,NSString *text) { if(size)snprintf(buffer,size,"%s",text.UTF8String ?: "unknown IOUSBHost error"); }
void *gu_usb_open(uint64_t id,char *message,size_t capacity) {
    @autoreleasepool {
        if(![IOUSBHostDevice instancesRespondToSelector:@selector(destroyWithOptions:)]) {error_text(message,capacity,@"Native ownership requires documented DeviceSurrender support; capture refused");return NULL;}
        io_service_t service=IOServiceGetMatchingService(kIOMainPortDefault,IORegistryEntryIDMatching(id));
        if (!service) {error_text(message,capacity,@"Selected USB attachment disappeared");return NULL;}
        NSError *error=nil;GuTransport *transport=[GuTransport new];
        // Modern Capture includes MSC interfaces. Ordinary destroy resets/rematches;
        // Rust selects explicit DeviceSurrender after any possible firmware submission.
        transport.device=[[IOUSBHostDevice alloc] initWithIOService:service options:IOUSBHostObjectInitOptionsDeviceCapture queue:nil error:&error interestHandler:nil];
        if (!transport.device) {IOObjectRelease(service);error_text(message,capacity,error.description);return NULL;}
        mach_timespec_t deadline={5,0};
        kern_return_t quiet=IOServiceWaitQuiet(service,&deadline);
        if(quiet!=KERN_SUCCESS){IOObjectRelease(service);error_text(message,capacity,[NSString stringWithFormat:@"Capture did not reach quiet state: 0x%x",quiet]);[transport.device destroy];return NULL;}
        io_iterator_t children=0;
        kern_return_t kr=IORegistryEntryCreateIterator(service,kIOServicePlane,kIORegistryIterateRecursively,&children);
        IOObjectRelease(service);
        if (kr) {error_text(message,capacity,@"Interface enumeration failed");[transport.device destroy];return NULL;}
        io_service_t child;unsigned matches=0;
        while ((child=IOIteratorNext(children))) {
            if (IOObjectConformsTo(child,"IOUSBHostInterface") && bot_profile(properties(child))) {
                matches++;
                if(matches==1) transport.interface=[[IOUSBHostInterface alloc] initWithIOService:child options:0 queue:nil error:&error interestHandler:nil];
            }
            IOObjectRelease(child);
        }
        IOObjectRelease(children);
        if(matches!=1 || !transport.interface) {error_text(message,capacity,error.description ?: @"Expected one BOT interface");[transport.interface destroy];[transport.device destroy];return NULL;}
        const IOUSBInterfaceDescriptor *interface=transport.interface.interfaceDescriptor;
        const IOUSBConfigurationDescriptor *config=transport.interface.configurationDescriptor;
        if(!interface || !config){error_text(message,capacity,@"Descriptors unavailable after capture");[transport.interface destroy];[transport.device destroy];return NULL;}
        const uint8_t *bytes=(const uint8_t *)config;
        NSUInteger total=OSSwapLittleToHostInt16(config->wTotalLength);
        uint8_t input=0,output=0;BOOL ours=NO,valid=YES;
        for(NSUInteger offset=0;offset+2<=total;) {
            uint8_t length=bytes[offset],type=bytes[offset+1];
            if(length<2 || offset+length>total){valid=NO;break;}
            if(type==4 && length>=9) ours=bytes[offset+2]==interface->bInterfaceNumber && bytes[offset+3]==interface->bAlternateSetting;
            if(ours && type==5 && length>=7 && (bytes[offset+3]&3)==2) {
                uint8_t address=bytes[offset+2];
                if(address&0x80){if(input)valid=NO;input=address;}else{if(output)valid=NO;output=address;}
            }
            offset+=length;
        }
        if(valid && input && output){transport.input=[transport.interface copyPipeWithAddress:input error:&error];transport.output=[transport.interface copyPipeWithAddress:output error:&error];}
        if(!transport.input || !transport.output){error_text(message,capacity,error.description ?: @"Invalid bulk endpoint descriptors");[transport.interface destroy];[transport.device destroy];return NULL;}
        transport.inputAddress=input;transport.outputAddress=output;
        return (__bridge_retained void *)transport;
    }
}
int gu_usb_transfer(void *context,int input,uint8_t *bytes,size_t length,size_t *actual,int *timed_out,char *message,size_t capacity) {
    @autoreleasepool {
        GuTransport *transport=(__bridge GuTransport *)context;
        NSMutableData *data=[NSMutableData dataWithLength:length];
        if(!input)memcpy(data.mutableBytes,bytes,length);
        NSError *error=nil;NSUInteger count=0;
        BOOL result=[(input ? transport.input : transport.output) sendIORequestWithData:data bytesTransferred:&count completionTimeout:5 error:&error];
        *actual=count;
        *timed_out=!result && (error.code==(NSInteger)(int32_t)kIOReturnTimeout || error.code==(NSInteger)(int32_t)kIOUSBTransactionTimeout);
        if(input)memcpy(bytes,data.bytes,MIN(count,length));
        if(!result)error_text(message,capacity,error.description);
        return result ? 0 : -1;
    }
}
void gu_usb_close(void *context,int surrender) {
    @autoreleasepool {
        GuTransport *transport=CFBridgingRelease(context);
        [transport.interface destroy];
        // DeviceSurrender is bit0 in the current public Apple SDK.
        [transport.device destroyWithOptions:surrender ? 1U : 0U];
    }
}
int gu_usb_max_lun(void *context,uint8_t *value,char *message,size_t capacity) {
    @autoreleasepool {
        GuTransport *transport=(__bridge GuTransport *)context;
        IOUSBDeviceRequest request={.bmRequestType=0xa1,.bRequest=0xfe,.wValue=0,.wIndex=transport.interface.interfaceDescriptor->bInterfaceNumber,.wLength=1};
        NSMutableData *data=[NSMutableData dataWithLength:1];NSUInteger actual=0;NSError *error=nil;
        BOOL result=[transport.interface sendDeviceRequest:request data:data bytesTransferred:&actual completionTimeout:5 error:&error];
        if(!result || actual!=1){error_text(message,capacity,error.description ?: @"Short GET_MAX_LUN");return -1;}
        *value=((const uint8_t *)data.bytes)[0];return 0;
    }
}
uint32_t gu_entry_hold(uint64_t id){return IOServiceGetMatchingService(kIOMainPortDefault,IORegistryEntryIDMatching(id));}
void gu_entry_release(uint32_t entry){IOObjectRelease(entry);}
int gu_usb_endpoint_status(void *context,int input,uint8_t *address,uint16_t *status,char *message,size_t capacity) {
    @autoreleasepool {
        GuTransport *transport=(__bridge GuTransport *)context;
        *address=input ? transport.inputAddress : transport.outputAddress;
        IOUSBDeviceRequest request={.bmRequestType=0x82,.bRequest=0,.wValue=0,.wIndex=*address,.wLength=2};
        NSMutableData *data=[NSMutableData dataWithLength:2];NSUInteger actual=0;NSError *error=nil;
        BOOL result=[transport.device sendDeviceRequest:request data:data bytesTransferred:&actual completionTimeout:5 error:&error];
        if(!result || actual!=2){error_text(message,capacity,error.description ?: @"Short endpoint GET_STATUS");return -1;}
        const uint8_t *bytes=data.bytes;*status=bytes[0]|((uint16_t)bytes[1]<<8);return 0;
    }
}
char *gu_usb_description(void *context){
    @autoreleasepool {
        GuTransport *transport=(__bridge GuTransport *)context;
        return strdup([NSString stringWithFormat:@"configuration=%u interface=%u alternate=%u bulk_in=0x%02x bulk_out=0x%02x",transport.interface.configurationDescriptor->bConfigurationValue,transport.interface.interfaceDescriptor->bInterfaceNumber,transport.interface.interfaceDescriptor->bAlternateSetting,transport.inputAddress,transport.outputAddress].UTF8String);
    }
}
