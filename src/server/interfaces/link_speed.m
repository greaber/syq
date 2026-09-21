// Keep Apple SDK layouts and Objective-C ownership on this side of the FFI.
// These read-only queries never launch a subprocess or change network settings.
#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/if_mib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <unistd.h>

double syq_macos_link_speed(const char *name) {
    if (strlen(name) >= IFNAMSIZ) {
        return 0;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    struct ifmediareq media = {0};
    strlcpy(media.ifm_name, name, sizeof(media.ifm_name));
    int result = ioctl(fd, SIOCGIFXMEDIA, &media);
    close(fd);
    if (result < 0 ||
        (media.ifm_status & (IFM_AVALID | IFM_ACTIVE)) != (IFM_AVALID | IFM_ACTIVE)) {
        return 0;
    }

    if (IFM_TYPE(media.ifm_active) == IFM_ETHER) {
        unsigned int index = if_nametoindex(name);
        if (index == 0) {
            return 0;
        }
        // ifmibdata uses if_data64: the baud rate does not wrap above 4 Gbit/s.
        // The active media check excludes disconnected interfaces.
        int mib[] = {CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_IFDATA,
                     (int)index, IFDATA_GENERAL};
        struct ifmibdata data = {0};
        size_t length = sizeof(data);
        if (sysctl(mib, 6, &data, &length, NULL, 0) != 0 ||
            length != sizeof(data) || strncmp(data.ifmd_name, name, IFNAMSIZ) != 0) {
            return 0;
        }
        return (double)data.ifmd_data.ifi_baudrate / 1000000.0;
    }

    if (IFM_TYPE(media.ifm_active) == IFM_IEEE80211) {
        @autoreleasepool {
            NSString *interfaceName = [NSString stringWithUTF8String:name];
            if (interfaceName == nil) {
                return 0;
            }
            CWInterface *interface =
                [[CWWiFiClient sharedWiFiClient] interfaceWithName:interfaceName];
            // Messaging nil and an unavailable transmit rate both return zero.
            return [interface transmitRate];
        }
    }
    return 0;
}
