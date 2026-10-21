#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>
#import <dispatch/dispatch.h>
#import <xpc/xpc.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// These values and identities are part of the bounded native/Rust contract.
static NSString *const kGUHelperMachService = @"lol.mjc.gulikit-updater.helper";
static NSString *const kGUHelperPlistName =
    @"lol.mjc.gulikit-updater.helper.plist";
static NSString *const kGUAppIdentifier = @"lol.mjc.gulikit-updater";
static NSString *const kGUHelperIdentifier = @"lol.mjc.gulikit-updater.helper";
static const uint64_t kGUProtocolVersion = 1;
static const uint32_t kGUMaximumPingTimeoutMs = 10000;
static const uint32_t kGUMaximumIdleTimeoutMs = 120000;

enum {
  GUHelperResultOK = 0,
  GUHelperResultUnsupportedOS = 1,
  GUHelperResultInvalidIdentity = 2,
  GUHelperResultService = 3,
  GUHelperResultConnection = 4,
  GUHelperResultTimeout = 5,
  GUHelperResultProtocol = 6,
  GUHelperResultPermission = 7,
  GUHelperResultWrongThread = 8,
};

enum {
  GUServiceStatusNotRegistered = 0,
  GUServiceStatusEnabled = 1,
  GUServiceStatusRequiresApproval = 2,
  GUServiceStatusNotFound = 3,
};

static void GUCopyError(char *destination, size_t capacity, NSString *message) {
  if (destination == NULL || capacity == 0) {
    return;
  }
  const char *utf8 = message.UTF8String;
  (void)snprintf(destination, capacity, "%s",
                 utf8 != NULL ? utf8 : "native helper error");
}

static NSString *GUStatusMessage(OSStatus status) {
  CFStringRef description = SecCopyErrorMessageString(status, NULL);
  if (description == NULL) {
    return [NSString
        stringWithFormat:@"code-signing validation failed (%d)", (int)status];
  }
  return CFBridgingRelease(description);
}

static BOOL GUIsValidTeamIdentifier(NSString *team) {
  if (team.length != 10) {
    return NO;
  }
  for (NSUInteger index = 0; index < team.length; index++) {
    unichar character = [team characterAtIndex:index];
    if (!((character >= 'A' && character <= 'Z') ||
          (character >= '0' && character <= '9'))) {
      return NO;
    }
  }
  return YES;
}

// Returns a Team ID only after the running executable's exact identifier and
// Apple trust chain have been verified. No environment value, request field, or
// caller-provided string participates.
static NSString *GUValidatedCurrentTeam(NSString *expectedIdentifier,
                                        char *error, size_t capacity) {
  SecCodeRef currentCode = NULL;
  SecStaticCodeRef staticCode = NULL;
  CFDictionaryRef signingInformation = NULL;
  SecRequirementRef requirement = NULL;
  NSString *identifier = nil;
  NSString *team = nil;
  NSString *requirementText = nil;
  OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &currentCode);
  if (status != errSecSuccess) {
    GUCopyError(error, capacity, GUStatusMessage(status));
    goto fail;
  }

  // Validate the dynamic process before reading static signing metadata, then
  // repeat the identity requirement against the dynamic code object after
  // extracting that metadata.
  status = SecCodeCheckValidity(currentCode, kSecCSDefaultFlags, NULL);
  if (status != errSecSuccess) {
    GUCopyError(error, capacity, GUStatusMessage(status));
    goto fail;
  }
  staticCode = (SecStaticCodeRef)currentCode;

  status = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation,
                                         &signingInformation);
  if (status != errSecSuccess) {
    GUCopyError(error, capacity, GUStatusMessage(status));
    goto fail;
  }

  CFTypeRef identifierValue =
      CFDictionaryGetValue(signingInformation, kSecCodeInfoIdentifier);
  CFTypeRef teamValue =
      CFDictionaryGetValue(signingInformation, kSecCodeInfoTeamIdentifier);
  if (identifierValue == NULL || teamValue == NULL ||
      CFGetTypeID(identifierValue) != CFStringGetTypeID() ||
      CFGetTypeID(teamValue) != CFStringGetTypeID()) {
    GUCopyError(error, capacity,
                @"the executable is ad hoc signed or has no Apple Team ID");
    goto fail;
  }

  identifier = [(__bridge NSString *)identifierValue copy];
  team = [(__bridge NSString *)teamValue copy];
  if (![identifier isEqualToString:expectedIdentifier] ||
      !GUIsValidTeamIdentifier(team)) {
    GUCopyError(error, capacity,
                @"the executable has an unexpected identifier or Team ID");
    goto fail;
  }

  requirementText =
      [NSString stringWithFormat:@"anchor apple generic and identifier \"%@\" "
                                 @"and certificate leaf[subject.OU] = \"%@\"",
                                 expectedIdentifier, team];
  status = SecRequirementCreateWithString((__bridge CFStringRef)requirementText,
                                          kSecCSDefaultFlags, &requirement);
  if (status != errSecSuccess) {
    GUCopyError(error, capacity, GUStatusMessage(status));
    goto fail;
  }
  status = SecCodeCheckValidity(currentCode, kSecCSDefaultFlags, requirement);
  if (status != errSecSuccess) {
    GUCopyError(error, capacity, GUStatusMessage(status));
    goto fail;
  }

  if (requirement != NULL) {
    CFRelease(requirement);
  }
  if (signingInformation != NULL) {
    CFRelease(signingInformation);
  }
  if (currentCode != NULL) {
    CFRelease(currentCode);
  }
  return team;

fail:
  if (requirement != NULL) {
    CFRelease(requirement);
  }
  if (signingInformation != NULL) {
    CFRelease(signingInformation);
  }
  if (currentCode != NULL) {
    CFRelease(currentCode);
  }
  return nil;
}

static NSString *GUPeerRequirement(NSString *identifier, NSString *team) {
  return
      [NSString stringWithFormat:@"anchor apple generic and identifier \"%@\" "
                                 @"and certificate leaf[subject.OU] = \"%@\"",
                                 identifier, team];
}

static SMAppService *GUService(void) API_AVAILABLE(macos(13.0)) {
  return [SMAppService daemonServiceWithPlistName:kGUHelperPlistName];
}

static uint32_t GUStatusValue(SMAppServiceStatus status)
    API_AVAILABLE(macos(13.0)) {
  switch (status) {
  case SMAppServiceStatusNotRegistered:
    return GUServiceStatusNotRegistered;
  case SMAppServiceStatusEnabled:
    return GUServiceStatusEnabled;
  case SMAppServiceStatusRequiresApproval:
    return GUServiceStatusRequiresApproval;
  case SMAppServiceStatusNotFound:
    return GUServiceStatusNotFound;
  }
  return UINT32_MAX;
}

int gulikit_helper_status(uint32_t *status, char *error, size_t capacity) {
  if (status == NULL) {
    GUCopyError(error, capacity, @"status output is required");
    return GUHelperResultProtocol;
  }
  *status = UINT32_MAX;
  @autoreleasepool {
    if (@available(macOS 13.0, *)) {
      SMAppService *service = GUService();
      if (service == nil) {
        GUCopyError(error, capacity,
                    @"SMAppService could not locate the bundled LaunchDaemon");
        return GUHelperResultService;
      }
      *status = GUStatusValue(service.status);
      if (*status == UINT32_MAX) {
        GUCopyError(error, capacity,
                    @"SMAppService returned an unknown status");
        return GUHelperResultProtocol;
      }
      return GUHelperResultOK;
    }
    GUCopyError(error, capacity, @"SMAppService requires macOS 13 or later");
    return GUHelperResultUnsupportedOS;
  }
}

int gulikit_helper_register(uint32_t *status, char *error, size_t capacity) {
  if (status == NULL) {
    GUCopyError(error, capacity, @"status output is required");
    return GUHelperResultProtocol;
  }
  *status = UINT32_MAX;
  @autoreleasepool {
    if (@available(macOS 13.0, *)) {
      if (GUValidatedCurrentTeam(kGUAppIdentifier, error, capacity) == nil) {
        return GUHelperResultInvalidIdentity;
      }
      SMAppService *service = GUService();
      if (service == nil) {
        GUCopyError(error, capacity,
                    @"SMAppService could not locate the bundled LaunchDaemon");
        return GUHelperResultService;
      }
      SMAppServiceStatus before = service.status;
      *status = GUStatusValue(before);
      if (before == SMAppServiceStatusEnabled ||
          before == SMAppServiceStatusRequiresApproval) {
        return GUHelperResultOK;
      }
      NSError *registrationError = nil;
      BOOL registered = [service registerAndReturnError:&registrationError];
      *status = GUStatusValue(service.status);
      if (!registered) {
        GUCopyError(error, capacity,
                    registrationError.localizedDescription
                        ?: @"registration failed");
        return GUHelperResultService;
      }
      return GUHelperResultOK;
    }
    GUCopyError(error, capacity, @"SMAppService requires macOS 13 or later");
    return GUHelperResultUnsupportedOS;
  }
}

int gulikit_helper_unregister(uint32_t *status, char *error, size_t capacity) {
  if (status == NULL) {
    GUCopyError(error, capacity, @"status output is required");
    return GUHelperResultProtocol;
  }
  *status = UINT32_MAX;
  @autoreleasepool {
    if (@available(macOS 13.0, *)) {
      if (GUValidatedCurrentTeam(kGUAppIdentifier, error, capacity) == nil) {
        return GUHelperResultInvalidIdentity;
      }
      SMAppService *service = GUService();
      if (service == nil) {
        GUCopyError(error, capacity,
                    @"SMAppService could not locate the bundled LaunchDaemon");
        return GUHelperResultService;
      }
      SMAppServiceStatus before = service.status;
      *status = GUStatusValue(before);
      if (before == SMAppServiceStatusNotRegistered) {
        return GUHelperResultOK;
      }
      NSError *unregistrationError = nil;
      BOOL unregistered =
          [service unregisterAndReturnError:&unregistrationError];
      *status = GUStatusValue(service.status);
      if (!unregistered) {
        GUCopyError(error, capacity,
                    unregistrationError.localizedDescription
                        ?: @"unregistration failed");
        return GUHelperResultService;
      }
      return GUHelperResultOK;
    }
    GUCopyError(error, capacity, @"SMAppService requires macOS 13 or later");
    return GUHelperResultUnsupportedOS;
  }
}

static BOOL GUDictionaryHasExactKeys(xpc_object_t dictionary, const char *first,
                                     const char *second, const char *third) {
  if (xpc_dictionary_get_count(dictionary) != 3) {
    return NO;
  }
  __block BOOL valid = YES;
  xpc_dictionary_apply(dictionary, ^bool(const char *key, xpc_object_t value) {
    (void)value;
    if (strcmp(key, first) != 0 && strcmp(key, second) != 0 &&
        strcmp(key, third) != 0) {
      valid = NO;
      return false;
    }
    return true;
  });
  return valid;
}

static BOOL GUIsUint64(xpc_object_t dictionary, const char *key) {
  xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
  return value != NULL && xpc_get_type(value) == XPC_TYPE_UINT64;
}

static BOOL GUIsString(xpc_object_t dictionary, const char *key,
                       const char *expected) {
  xpc_object_t value = xpc_dictionary_get_value(dictionary, key);
  if (value == NULL || xpc_get_type(value) != XPC_TYPE_STRING) {
    return NO;
  }
  const char *string = xpc_string_get_string_ptr(value);
  return string != NULL && strcmp(string, expected) == 0;
}

static int GUValidatePingReply(xpc_object_t reply, uint64_t requestIdentifier) {
  if (reply == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT) {
    return GUHelperResultInvalidIdentity;
  }
  if (reply == XPC_ERROR_CONNECTION_INTERRUPTED ||
      reply == XPC_ERROR_CONNECTION_INVALID) {
    return GUHelperResultConnection;
  }
  if (reply == NULL || xpc_get_type(reply) != XPC_TYPE_DICTIONARY ||
      !GUDictionaryHasExactKeys(reply, "kind", "protocol_version",
                                "request_id") ||
      !GUIsUint64(reply, "protocol_version") ||
      xpc_dictionary_get_uint64(reply, "protocol_version") !=
          kGUProtocolVersion ||
      !GUIsUint64(reply, "request_id") ||
      xpc_dictionary_get_uint64(reply, "request_id") != requestIdentifier) {
    return GUHelperResultProtocol;
  }
  if (GUIsString(reply, "kind", "pong")) {
    return GUHelperResultOK;
  }
  return GUHelperResultProtocol;
}

@interface GUPingWaiter : NSObject
@property(nonatomic, strong) dispatch_semaphore_t semaphore;
@property(nonatomic) int result;
@property(nonatomic) BOOL finished;
@property(nonatomic) BOOL peerAccepted;
- (void)markPeerAccepted;
- (BOOL)wasPeerAccepted;
- (void)finishWithResult:(int)result;
- (int)resultValue;
@end

@implementation GUPingWaiter
- (void)markPeerAccepted {
  @synchronized(self) {
    self.peerAccepted = YES;
  }
}
- (BOOL)wasPeerAccepted {
  @synchronized(self) {
    return self.peerAccepted;
  }
}
- (void)finishWithResult:(int)result {
  @synchronized(self) {
    if (self.finished) {
      return;
    }
    self.result = result;
    self.finished = YES;
    dispatch_semaphore_signal(self.semaphore);
  }
}
- (int)resultValue {
  @synchronized(self) {
    return self.result;
  }
}
@end

static int GUPingAvailable(uint32_t timeout_ms, char *error, size_t capacity)
    API_AVAILABLE(macos(13.0)) {
  if (timeout_ms == 0 || timeout_ms > kGUMaximumPingTimeoutMs) {
    GUCopyError(error, capacity,
                @"Ping timeout is outside its supported range");
    return GUHelperResultProtocol;
  }
  @autoreleasepool {
    NSString *team = GUValidatedCurrentTeam(kGUAppIdentifier, error, capacity);
    if (team == nil) {
      return GUHelperResultInvalidIdentity;
    }
    NSString *requirement = GUPeerRequirement(kGUHelperIdentifier, team);
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    xpc_connection_t connection = xpc_connection_create_mach_service(
        kGUHelperMachService.UTF8String, queue,
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (connection == NULL) {
      GUCopyError(error, capacity, @"XPC could not create a helper connection");
      return GUHelperResultConnection;
    }
    int requirementResult = xpc_connection_set_peer_code_signing_requirement(
        connection, requirement.UTF8String);
    if (requirementResult != 0) {
      xpc_connection_cancel(connection);
      GUCopyError(error, capacity,
                  @"XPC rejected the helper signing requirement");
      return GUHelperResultInvalidIdentity;
    }

    GUPingWaiter *waiter = [GUPingWaiter new];
    waiter.semaphore = dispatch_semaphore_create(0);
    waiter.result = GUHelperResultConnection;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
      if (event == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT) {
        [waiter finishWithResult:GUHelperResultInvalidIdentity];
      } else if (event == XPC_ERROR_CONNECTION_INTERRUPTED ||
                 event == XPC_ERROR_CONNECTION_INVALID) {
        [waiter finishWithResult:GUHelperResultConnection];
      }
    });
    xpc_connection_resume(connection);

    uint64_t requestIdentifier = 0;
    arc4random_buf(&requestIdentifier, sizeof(requestIdentifier));
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    if (request == NULL) {
      xpc_connection_cancel(connection);
      GUCopyError(error, capacity,
                  @"could not allocate the bounded Ping request");
      return GUHelperResultConnection;
    }
    xpc_dictionary_set_string(request, "kind", "ping");
    xpc_dictionary_set_uint64(request, "protocol_version", kGUProtocolVersion);
    xpc_dictionary_set_uint64(request, "request_id", requestIdentifier);

    xpc_connection_send_message_with_reply(
        connection, request, queue, ^(xpc_object_t reply) {
          // The asynchronous reply confirms that the on-demand service
          // connection exists. Only then is the remote EUID meaningful; the
          // request itself is a side-effect-free Ping.
          int replyResult = GUValidatePingReply(reply, requestIdentifier);
          if (replyResult != GUHelperResultOK) {
            [waiter finishWithResult:replyResult];
          } else if (xpc_connection_get_euid(connection) != 0) {
            [waiter finishWithResult:GUHelperResultPermission];
          } else {
            [waiter finishWithResult:GUHelperResultOK];
          }
        });
    dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC);
    long waitResult = dispatch_semaphore_wait(waiter.semaphore, deadline);
    if (waitResult != 0) {
      xpc_connection_cancel(connection);
      GUCopyError(error, capacity,
                  @"the helper did not answer before the Ping deadline");
      return GUHelperResultTimeout;
    }
    int result = waiter.resultValue;
    xpc_connection_cancel(connection);
    if (result != GUHelperResultOK) {
      if (result == GUHelperResultPermission) {
        GUCopyError(error, capacity,
                    @"the connected helper is not running as root");
      } else if (result == GUHelperResultInvalidIdentity) {
        GUCopyError(error, capacity,
                    @"the connected peer failed its signing requirement");
      } else if (result == GUHelperResultConnection) {
        GUCopyError(error, capacity,
                    @"the XPC connection failed before a valid reply");
      } else {
        GUCopyError(error, capacity,
                    @"the helper returned an invalid Ping response");
      }
      return result;
    }
    return GUHelperResultOK;
  }
}

int gulikit_helper_ping(uint32_t timeout_ms, char *error, size_t capacity) {
  if (@available(macOS 13.0, *)) {
    return GUPingAvailable(timeout_ms, error, capacity);
  }
  GUCopyError(error, capacity,
              @"the privileged helper requires macOS 13 or later");
  return GUHelperResultUnsupportedOS;
}

static BOOL GUValidPingRequest(xpc_object_t request,
                               uint64_t *requestIdentifier) {
  if (request == NULL || xpc_get_type(request) != XPC_TYPE_DICTIONARY ||
      !GUDictionaryHasExactKeys(request, "kind", "protocol_version",
                                "request_id") ||
      !GUIsString(request, "kind", "ping") ||
      !GUIsUint64(request, "protocol_version") ||
      xpc_dictionary_get_uint64(request, "protocol_version") !=
          kGUProtocolVersion ||
      !GUIsUint64(request, "request_id")) {
    return NO;
  }
  *requestIdentifier = xpc_dictionary_get_uint64(request, "request_id");
  return YES;
}

// Test-only in-process protocol fixtures exercise the same XPC-object validator
// used by the listener. They never open a Mach service or change SMAppService
// state.
int gulikit_helper_test_ping_request(uint32_t case_id) {
  @autoreleasepool {
    if (case_id > 6) {
      return -1;
    }
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    if (request == NULL) {
      return -1;
    }
    xpc_dictionary_set_string(request, "kind",
                              case_id == 1 ? "not-ping" : "ping");
    if (case_id == 1) {
      xpc_dictionary_set_uint64(request, "protocol_version",
                                kGUProtocolVersion);
      xpc_dictionary_set_uint64(request, "request_id", 42);
    } else {
      if (case_id == 5) {
        xpc_dictionary_set_string(request, "extra", "rejected");
      }
      if (case_id == 2) {
        xpc_dictionary_set_string(request, "protocol_version", "1");
      } else if (case_id == 3) {
        xpc_dictionary_set_uint64(request, "protocol_version",
                                  kGUProtocolVersion + 1);
      } else {
        xpc_dictionary_set_uint64(request, "protocol_version",
                                  kGUProtocolVersion);
      }
      if (case_id == 4) {
        xpc_dictionary_set_string(request, "request_id", "42");
      } else if (case_id != 6) {
        xpc_dictionary_set_uint64(request, "request_id", 42);
      }
    }
    uint64_t requestIdentifier = 0;
    return GUValidPingRequest(request, &requestIdentifier) ? 1 : 0;
  }
}

int gulikit_helper_test_ping_reply(uint32_t case_id) {
  @autoreleasepool {
    if (case_id > 6) {
      return -1;
    }
    xpc_object_t reply = xpc_dictionary_create(NULL, NULL, 0);
    if (reply == NULL) {
      return -1;
    }
    xpc_dictionary_set_string(reply, "kind", case_id == 1 ? "error" : "pong");
    if (case_id == 5) {
      xpc_dictionary_set_string(reply, "extra", "rejected");
    }
    if (case_id == 3) {
      xpc_dictionary_set_string(reply, "protocol_version", "1");
    } else if (case_id == 2) {
      xpc_dictionary_set_uint64(reply, "protocol_version",
                                kGUProtocolVersion + 1);
    } else if (case_id != 6) {
      xpc_dictionary_set_uint64(reply, "protocol_version", kGUProtocolVersion);
    }
    xpc_dictionary_set_uint64(reply, "request_id", case_id == 4 ? 41 : 42);
    return GUValidatePingReply(reply, 42) == GUHelperResultOK ? 1 : 0;
  }
}

static void GUSendPingResponse(xpc_connection_t peer, xpc_object_t request,
                               uint64_t requestIdentifier, BOOL valid) {
  xpc_object_t reply = xpc_dictionary_create_reply(request);
  if (reply == NULL) {
    xpc_connection_cancel(peer);
    return;
  }
  xpc_dictionary_set_string(reply, "kind", valid ? "pong" : "error");
  xpc_dictionary_set_uint64(reply, "protocol_version", kGUProtocolVersion);
  xpc_dictionary_set_uint64(reply, "request_id", requestIdentifier);
  xpc_connection_send_message(peer, reply);
}

int gulikit_helper_test_ping_round_trip(uint32_t timeout_ms) {
  if (timeout_ms == 0 || timeout_ms > 2000) {
    return GUHelperResultProtocol;
  }
  @autoreleasepool {
    dispatch_queue_t queue =
        dispatch_queue_create("gulikit.helper.xpc-test", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t peerClosed = dispatch_semaphore_create(0);
    GUPingWaiter *waiter = [GUPingWaiter new];
    waiter.semaphore = dispatch_semaphore_create(0);
    waiter.result = GUHelperResultConnection;
    xpc_connection_t listener = xpc_connection_create(NULL, queue);
    if (listener == NULL) {
      return GUHelperResultConnection;
    }

    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
      @autoreleasepool {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) {
          return;
        }
        xpc_connection_t peer = (xpc_connection_t)event;
        xpc_connection_set_target_queue(peer, queue);
        [waiter markPeerAccepted];
        __block BOOL closed = NO;
        xpc_connection_set_event_handler(peer, ^(xpc_object_t peerEvent) {
          @autoreleasepool {
            if (peerEvent == XPC_ERROR_CONNECTION_INVALID) {
              xpc_connection_set_event_handler(peer,
                                               ^(xpc_object_t ignoredEvent) {
                                                 (void)ignoredEvent;
                                               });
              if (!closed) {
                closed = YES;
                dispatch_semaphore_signal(peerClosed);
              }
              xpc_connection_cancel(peer);
              return;
            }
            if (xpc_get_type(peerEvent) != XPC_TYPE_DICTIONARY) {
              return;
            }
            uint64_t requestIdentifier = 0;
            BOOL validRequest =
                GUValidPingRequest(peerEvent, &requestIdentifier);
            GUSendPingResponse(peer, peerEvent, requestIdentifier,
                               validRequest);
          }
        });
        xpc_connection_resume(peer);
      }
    });
    xpc_connection_resume(listener);

    xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
    if (endpoint == NULL) {
      xpc_connection_cancel(listener);
      return GUHelperResultConnection;
    }
    xpc_connection_t client = xpc_connection_create_from_endpoint(endpoint);
    if (client == NULL) {
      xpc_connection_cancel(listener);
      return GUHelperResultConnection;
    }
    xpc_connection_set_event_handler(client, ^(xpc_object_t event) {
      if (event == XPC_ERROR_CONNECTION_INVALID ||
          event == XPC_ERROR_CONNECTION_INTERRUPTED) {
        [waiter finishWithResult:GUHelperResultConnection];
      }
    });
    xpc_connection_resume(client);

    uint64_t requestIdentifier = 42;
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    if (request == NULL) {
      xpc_connection_cancel(client);
      xpc_connection_cancel(listener);
      return GUHelperResultConnection;
    }
    xpc_dictionary_set_string(request, "kind", "ping");
    xpc_dictionary_set_uint64(request, "protocol_version", kGUProtocolVersion);
    xpc_dictionary_set_uint64(request, "request_id", requestIdentifier);
    xpc_connection_send_message_with_reply(
        client, request, queue, ^(xpc_object_t reply) {
          [waiter
              finishWithResult:GUValidatePingReply(reply, requestIdentifier)];
        });

    dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeout_ms * NSEC_PER_MSEC);
    long waitResult = dispatch_semaphore_wait(waiter.semaphore, deadline);
    int result = waitResult == 0 ? waiter.resultValue : GUHelperResultTimeout;
    xpc_connection_cancel(client);
    xpc_connection_cancel(listener);
    if ([waiter wasPeerAccepted]) {
      dispatch_time_t closeDeadline =
          dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 2);
      (void)dispatch_semaphore_wait(peerClosed, closeDeadline);
    }
    return result;
  }
}

static void GUScheduleIdleExit(dispatch_source_t idleTimer,
                               uint32_t idleTimeoutMs) {
  dispatch_source_set_timer(
      idleTimer,
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)idleTimeoutMs * NSEC_PER_MSEC),
      DISPATCH_TIME_FOREVER, NSEC_PER_SEC / 10);
}

typedef struct {
  uint32_t activePeers;
  uint64_t generation;
} GUIdleState;

static void GUIdlePeerOpened(GUIdleState *state) {
  state->activePeers++;
  state->generation++;
}

static void GUIdlePeerClosed(GUIdleState *state) {
  if (state->activePeers > 0) {
    state->activePeers--;
  }
  state->generation++;
}

static BOOL GUIdleCanExit(const GUIdleState *state, uint64_t generation) {
  return state->activePeers == 0 && state->generation == generation;
}

int gulikit_helper_test_idle_transition(uint32_t case_id) {
  GUIdleState state = {0, 0};
  uint64_t scheduledGeneration = state.generation;
  switch (case_id) {
  case 0:
    break;
  case 1:
    GUIdlePeerOpened(&state);
    break;
  case 2:
    GUIdlePeerOpened(&state);
    GUIdlePeerClosed(&state);
    break;
  case 3:
    GUIdlePeerOpened(&state);
    GUIdlePeerClosed(&state);
    scheduledGeneration = state.generation;
    break;
  default:
    return -1;
  }
  return GUIdleCanExit(&state, scheduledGeneration) ? 1 : 0;
}

static int GUServePingAvailable(uint32_t idle_timeout_ms, char *error,
                                size_t capacity) API_AVAILABLE(macos(13.0)) {
  if (idle_timeout_ms == 0 || idle_timeout_ms > kGUMaximumIdleTimeoutMs) {
    GUCopyError(error, capacity,
                @"idle timeout is outside its supported range");
    return GUHelperResultProtocol;
  }
  if (geteuid() != 0) {
    GUCopyError(error, capacity, @"the launchd helper must run as root");
    return GUHelperResultPermission;
  }
  if (pthread_main_np() == 0) {
    GUCopyError(error, capacity,
                @"the helper listener must run on the process main thread");
    return GUHelperResultWrongThread;
  }
  @autoreleasepool {
    NSString *team =
        GUValidatedCurrentTeam(kGUHelperIdentifier, error, capacity);
    if (team == nil) {
      return GUHelperResultInvalidIdentity;
    }
    NSString *requirement = GUPeerRequirement(kGUAppIdentifier, team);
    dispatch_queue_t queue = dispatch_queue_create(
        "lol.mjc.gulikit-updater.helper", DISPATCH_QUEUE_SERIAL);
    xpc_connection_t listener = xpc_connection_create_mach_service(
        kGUHelperMachService.UTF8String, queue,
        XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (listener == NULL) {
      GUCopyError(error, capacity, @"XPC could not create the helper listener");
      return GUHelperResultConnection;
    }
    if (xpc_connection_set_peer_code_signing_requirement(
            listener, requirement.UTF8String) != 0) {
      xpc_connection_cancel(listener);
      GUCopyError(error, capacity, @"XPC rejected the GUI signing requirement");
      return GUHelperResultInvalidIdentity;
    }

    __block GUIdleState idleState = {0, 0};
    dispatch_source_t idleTimer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    if (idleTimer == NULL) {
      xpc_connection_cancel(listener);
      GUCopyError(error, capacity,
                  @"the helper could not create its idle timer");
      return GUHelperResultConnection;
    }
    dispatch_source_set_event_handler(idleTimer, ^{
      if (idleState.activePeers != 0) {
        return;
      }
      uint64_t generation = idleState.generation;
      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_MSEC * 100),
                     queue, ^{
                       @autoreleasepool {
                         if (GUIdleCanExit(&idleState, generation)) {
                           xpc_connection_cancel(listener);
                           exit(0);
                         }
                       }
                     });
    });
    dispatch_resume(idleTimer);
    GUScheduleIdleExit(idleTimer, idle_timeout_ms);

    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
      @autoreleasepool {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) {
          return;
        }
        xpc_connection_t peer = (xpc_connection_t)event;
        xpc_connection_set_target_queue(peer, queue);
        if (xpc_connection_set_peer_code_signing_requirement(
                peer, requirement.UTF8String) != 0) {
          xpc_connection_cancel(peer);
          return;
        }
        uid_t peerEffectiveUID = xpc_connection_get_euid(peer);
        if (peerEffectiveUID == 0 || peerEffectiveUID == (uid_t)-1) {
          xpc_connection_cancel(peer);
          return;
        }

        GUIdlePeerOpened(&idleState);
        dispatch_source_set_timer(idleTimer, DISPATCH_TIME_FOREVER,
                                  DISPATCH_TIME_FOREVER, 0);
        __block BOOL counted = YES;
        xpc_connection_set_event_handler(peer, ^(xpc_object_t peerEvent) {
          @autoreleasepool {
            if (peerEvent == XPC_ERROR_CONNECTION_INVALID ||
                peerEvent == XPC_ERROR_TERMINATION_IMMINENT) {
              // The connection retains its event-handler block and the block
              // retains the connection. Replace the handler on a terminal event
              // to break that cycle.
              xpc_connection_set_event_handler(peer,
                                               ^(xpc_object_t ignoredEvent) {
                                                 (void)ignoredEvent;
                                               });
              xpc_connection_cancel(peer);
              if (counted) {
                counted = NO;
                GUIdlePeerClosed(&idleState);
                if (idleState.activePeers == 0) {
                  GUScheduleIdleExit(idleTimer, idle_timeout_ms);
                }
              }
              return;
            }
            if (xpc_get_type(peerEvent) != XPC_TYPE_DICTIONARY) {
              return;
            }
            uint64_t requestIdentifier = 0;
            BOOL validRequest =
                GUValidPingRequest(peerEvent, &requestIdentifier);
            GUSendPingResponse(peer, peerEvent, requestIdentifier,
                               validRequest);
          }
        });
        xpc_connection_resume(peer);
      }
    });
    xpc_connection_resume(listener);
    dispatch_main();
    __builtin_unreachable();
  }
}

int gulikit_helper_serve_ping(uint32_t idle_timeout_ms, char *error,
                              size_t capacity) {
  if (@available(macOS 13.0, *)) {
    return GUServePingAvailable(idle_timeout_ms, error, capacity);
  }
  GUCopyError(error, capacity,
              @"the privileged helper requires macOS 13 or later");
  return GUHelperResultUnsupportedOS;
}
