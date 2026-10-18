#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOUSBHost/IOUSBHost.h>
#include <unistd.h>

// NS39 Bluetooth update identity observed on this Mac. No flash command exists here.
static const uint16_t vendor = 0x34d3, product = 0x1100;
static void hex(const void *p, NSUInteger n) {
    const uint8_t *b = p;
    for (NSUInteger i = 0; i < n; ++i) printf("%02x%s", b[i], i + 1 == n ? "\n" : " ");
}
static BOOL transfer(IOUSBHostPipe *pipe, NSMutableData *data) {
    NSError *error = nil;
    NSUInteger n = 0;
    BOOL ok = [pipe sendIORequestWithData:data bytesTransferred:&n completionTimeout:5 error:&error];
    if (!ok || n != data.length) {
        fprintf(stderr, "USB transfer: %s, got %lu/%lu bytes\n", error.description.UTF8String ?: "short transfer", (unsigned long)n, (unsigned long)data.length);
        return NO;
    }
    return YES;
}
static int probe(io_service_t service, BOOL inquiry) {
    NSError *error = nil;
    IOUSBHostDevice *device = [[IOUSBHostDevice alloc] initWithIOService:service options:IOUSBHostObjectInitOptionsDeviceCapture queue:nil error:&error interestHandler:nil];
    if (!device) { fprintf(stderr, "Capture failed: %s\n", error.description.UTF8String); return 3; }
    int result = 4;
    IOUSBHostInterface *interface = nil;
    @try {
        io_iterator_t children = 0;
        kern_return_t kr = IORegistryEntryCreateIterator(service, kIOServicePlane, kIORegistryIterateRecursively, &children);
        if (kr != KERN_SUCCESS) { fprintf(stderr, "Interface enumeration: 0x%x\n", kr); return result; }
        io_service_t child;
        while ((child = IOIteratorNext(children))) {
            if (IOObjectConformsTo(child, "IOUSBHostInterface")) {
                interface = [[IOUSBHostInterface alloc] initWithIOService:child options:0 queue:nil error:&error interestHandler:nil];
                IOObjectRelease(child);
                break;
            }
            IOObjectRelease(child);
        }
        IOObjectRelease(children);
        if (!interface) { fprintf(stderr, "Interface open failed: %s\n", error.description.UTF8String ?: "not found"); return result; }
        const IOUSBInterfaceDescriptor *id = interface.interfaceDescriptor;
        if (id->bInterfaceClass != 8 || id->bInterfaceSubClass != 6 || id->bInterfaceProtocol != 0x50) {
            fprintf(stderr, "Unexpected interface class/subclass/protocol\n"); return result;
        }
        const IOUSBConfigurationDescriptor *config = interface.configurationDescriptor;
        const uint8_t *bytes = (const uint8_t *)config;
        NSUInteger total = OSSwapLittleToHostInt16(config->wTotalLength);
        uint8_t inAddress = 0, outAddress = 0;
        BOOL ours = NO;
        for (NSUInteger p = 0; p + 2 <= total;) {
            uint8_t length = bytes[p], type = bytes[p + 1];
            if (length < 2 || p + length > total) { fprintf(stderr, "Invalid descriptor\n"); return result; }
            if (type == 4 && length >= 9) ours = bytes[p+2] == id->bInterfaceNumber && bytes[p+3] == id->bAlternateSetting;
            if (ours && type == 5 && length >= 7 && (bytes[p+3] & 3) == 2) {
                if (bytes[p+2] & 0x80) inAddress = bytes[p+2]; else outAddress = bytes[p+2];
            }
            p += length;
        }
        printf("Mass-storage BOT interface %u, bulk OUT 0x%02x, IN 0x%02x\n", id->bInterfaceNumber, outAddress, inAddress);
        if (!inAddress || !outAddress) return result;
        IOUSBHostPipe *in = [interface copyPipeWithAddress:inAddress error:&error];
        IOUSBHostPipe *out = [interface copyPipeWithAddress:outAddress error:&error];
        if (!in || !out) { fprintf(stderr, "Pipe open failed: %s\n", error.description.UTF8String); return result; }
        // Capture can interrupt a kernel storage transaction. Synchronize BOT first.
        IOUSBDeviceRequest reset = {.bmRequestType = 0x21, .bRequest = 0xff, .wValue = 0, .wIndex = id->bInterfaceNumber, .wLength = 0};
        if (![interface sendDeviceRequest:reset error:&error] || ![in clearStallWithError:&error] || ![out clearStallWithError:&error]) {
            fprintf(stderr, "BOT reset failed: %s\n", error.description.UTF8String); return result;
        }
        puts("BOT reset complete"); fflush(stdout);
        // USB Mass Storage CBW: signature, tag, transfer length, IN, LUN0, CDB length10.
        // The ONLY vendor opcode this program can send is F1: read20-byte identity/version.
        uint8_t cbw[31] = {0x55,0x53,0x42,0x43, 0x47,0x55,0x4c,0x49, 20,0,0,0, 0x80,0,10, 0xf1};
        if (inquiry) { cbw[8] = 36; cbw[14] = 6; memset(cbw + 15, 0, 16); cbw[15] = 0x12; cbw[19] = 36; }
        NSMutableData *command = [NSMutableData dataWithBytes:cbw length:sizeof(cbw)];
        NSMutableData *info = [NSMutableData dataWithLength:inquiry ? 36 : 20];
        NSMutableData *status = [NSMutableData dataWithLength:13];
        printf("Sending %s command: ", inquiry ? "standard INQUIRY" : "F1 identity"); hex(cbw, sizeof(cbw)); fflush(stdout);
        if (!transfer(out, command)) return result;
        puts("Reading F1 data"); fflush(stdout);
        if (!transfer(in, info)) return result;
        puts("Reading BOT command status"); fflush(stdout);
        if (!transfer(in, status)) return result;
        printf("%s response: ", inquiry ? "INQUIRY" : "F1"); hex(info.bytes, info.length);
        printf("BOT CSW: "); hex(status.bytes, status.length);
        const uint8_t *s = status.bytes, *b = info.bytes;
        if (memcmp(s, "USBS", 4) || memcmp(s + 4, cbw + 4, 4) || s[8] || s[9] || s[10] || s[11] || s[12]) {
            fprintf(stderr, "Invalid/failing BOT status\n"); return result;
        }
        if (inquiry) { puts("Standard read-only SCSI INQUIRY passed"); return 0; }
        const uint8_t expected[16] = {0xa1,0xca,0x51,0xda,0x72,0x4c,0xb6,0x10,0x36,0x58,0xc0,0x5d,0x7d,0x4e,0x15,0x96};
        if (memcmp(b, expected, 16)) { fprintf(stderr, "Identity differs from official NS38/39/59 updater\n"); return result; }
        unsigned version = b[16] | ((unsigned)b[17] << 8);
        printf("Official updater identity matched. BT firmware %u.%02u. No firmware bytes written.\n", version / 100, version % 100);
        result = 0;
    } @finally {
        [interface destroy];
        [device destroy]; // Return the device to normal macOS driver matching.
    }
    return result;
}
int main(int argc, const char **argv) {
    @autoreleasepool {
        BOOL inquiry = argc == 2 && strcmp(argv[1], "--inquiry") == 0;
        BOOL read = argc == 2 && (strcmp(argv[1], "--read-info") == 0 || inquiry);
        if (argc != 2 || (!read && strcmp(argv[1], "--list") != 0)) {
            fprintf(stderr, "Usage: %s --list | --read-info | --inquiry\n", argv[0]); return 2;
        }
        if (read && geteuid() != 0) { fprintf(stderr, "Read probe requires sudo for temporary USB capture. This probe cannot flash firmware.\n"); return 2; }
        NSMutableDictionary *match = CFBridgingRelease(IOServiceMatching("IOUSBHostDevice"));
        match[@"idVendor"] = @(vendor); match[@"idProduct"] = @(product);
        io_iterator_t iterator = 0;
        kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, (__bridge_retained CFDictionaryRef)match, &iterator);
        if (kr != KERN_SUCCESS) { fprintf(stderr, "Enumeration failed: 0x%x\n", kr); return 3; }
        io_service_t service = IOIteratorNext(iterator), second = IOIteratorNext(iterator);
        IOObjectRelease(iterator);
        if (second) { IOObjectRelease(second); IOObjectRelease(service); fprintf(stderr, "More than one matching device; refusing ambiguous target.\n"); return 3; }
        if (!service) { fprintf(stderr, "No NS39 Bluetooth updater device 34d3:1100. Enter Gear+A mode and retry.\n"); return 3; }
        printf("Found Bluetooth updater USB device 34d3:1100\n"); fflush(stdout);
        int result = read ? probe(service, inquiry) : 0;
        IOObjectRelease(service);
        return result;
    }
}
