#include "syscall_utils.h"
#include <ctype.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

// Android NDK may not expose socket syscall numbers; use Linux aarch64 values
#if defined(__aarch64__)
#ifndef __NR_socket
#define __NR_socket   198
#define __NR_connect  203
#define __NR_setsockopt 208
#define __NR_sendto   206
#define __NR_recvfrom 207
#endif
#ifndef __NR_lseek
#define __NR_lseek    62
#endif
#elif defined(__arm__)
#ifndef __NR_socketcall
#define __NR_socketcall 281
#endif
#endif

// Architecture-specific syscall implementation
#if defined(__arm__)
static inline long do_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    register long r7 __asm__("r7") = number;
    register long r0 __asm__("r0") = arg1;
    register long r1 __asm__("r1") = arg2;
    register long r2 __asm__("r2") = arg3;
    register long r3 __asm__("r3") = arg4;
    register long r4 __asm__("r4") = arg5;
    register long r5 __asm__("r5") = arg6;

    __asm__ __volatile__(
        "swi 0"
        : "=r"(r0)
        : "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
        : "memory"
    );

    return r0;
}
#elif defined(__aarch64__)
static inline long do_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x3 __asm__("x3") = arg4;
    register long x4 __asm__("x4") = arg5;
    register long x5 __asm__("x5") = arg6;

    __asm__ __volatile__(
        "svc 0"
        : "=r"(x0)
        : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory"
    );

    return x0;
}
#elif defined(__i386__)
static inline long do_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long result;
    __asm__ __volatile__(
        "int $0x80"
        : "=a"(result)
        : "a"(number), "b"(arg1), "c"(arg2), "d"(arg3), "S"(arg4), "D"(arg5)
        : "memory"
    );
    return result;
}
#elif defined(__x86_64__)
static inline long do_syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long result;
    register long r10 __asm__("r10") = arg4;
    register long r8 __asm__("r8") = arg5;
    register long r9 __asm__("r9") = arg6;

    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return result;
}
#else
    #error "Unsupported architecture"
#endif

// Syscall wrappers
ssize_t my_read(int fd, void *buf, size_t count) {
    return do_syscall(__NR_read, fd, (long)buf, count, 0, 0, 0);
}

ssize_t my_write(int fd, const void *buf, size_t count) {
    return do_syscall(__NR_write, fd, (long)buf, count, 0, 0, 0);
}

// Use direct open syscall instead of openat
int my_open(const char *pathname, int flags, mode_t mode) {
#if defined(__NR_open)
    return do_syscall(__NR_open, (long)pathname, flags, mode, 0, 0, 0);
#else
    // Fallback to openat with AT_FDCWD
    return do_syscall(__NR_openat, -100, (long)pathname, flags, mode, 0, 0);
#endif
}

int my_close(int fd) {
    return do_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}

int my_access(const char *pathname, int mode) {
#if defined(__NR_access)
    return do_syscall(__NR_access, (long)pathname, mode, 0, 0, 0, 0);
#else
    return do_syscall(__NR_faccessat, -100, (long)pathname, mode, 0, 0, 0);
#endif
}

#if defined(__NR_lseek)
ssize_t my_lseek(int fd, off_t offset, int whence) {
    return (ssize_t) do_syscall(__NR_lseek, fd, (long)offset, whence, 0, 0, 0);
}
#else
ssize_t my_lseek(int fd, off_t offset, int whence) {
    (void)fd;
    (void)offset;
    (void)whence;
    return -1;
}
#endif

#if defined(__NR_socket) && defined(__NR_connect) && defined(__NR_setsockopt)
int my_socket(int domain, int type, int protocol) {
    return (int) do_syscall(__NR_socket, domain, type, protocol, 0, 0, 0);
}
int my_connect(int sockfd, const void *addr, unsigned int addrlen) {
    return (int) do_syscall(__NR_connect, sockfd, (long)addr, addrlen, 0, 0, 0);
}
int my_setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen) {
    return (int) do_syscall(__NR_setsockopt, sockfd, level, optname, (long)optval, optlen, 0);
}
#endif
#if defined(__NR_sendto) && defined(__NR_recvfrom)
/* Stream send/recv via sendto/recvfrom with null address (bypass libc for D-Bus probe) */
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    return (ssize_t) do_syscall(__NR_sendto, sockfd, (long)buf, len, flags, 0, 0);
}
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) {
    return (ssize_t) do_syscall(__NR_recvfrom, sockfd, (long)buf, len, flags, 0, 0);
}
#else
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) { (void)sockfd;(void)buf;(void)len;(void)flags; return -1; }
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags) { (void)sockfd;(void)buf;(void)len;(void)flags; return -1; }
#endif
#if !defined(__NR_socket) || !defined(__NR_connect) || !defined(__NR_setsockopt)
int my_socket(int domain, int type, int protocol) { (void)domain;(void)type;(void)protocol; return -1; }
int my_connect(int sockfd, const void *addr, unsigned int addrlen) { (void)sockfd;(void)addr;(void)addrlen; return -1; }
int my_setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen) { (void)sockfd;(void)level;(void)optname;(void)optval;(void)optlen; return -1; }
#endif

// String operations (reimplementations to avoid libc)
char *my_strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

char *my_strncpy(char *dest, const char *src, size_t n) {
    char *d = dest;
    while (n && (*d++ = *src++)) {
        n--;
    }
    while (n--) {
        *d++ = '\0';
    }
    return dest;
}

int my_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int my_strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *my_strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;

    const char *h = haystack;
    while (*h) {
        const char *h2 = h;
        const char *n = needle;
        while (*h2 && *n && *h2 == *n) {
            h2++;
            n++;
        }
        if (!*n) return (char *)h;
        h++;
    }
    return nullptr;
}

char *my_strcasestr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;

    const char *h = haystack;
    while (*h) {
        const char *h2 = h;
        const char *n = needle;
        while (*h2 && *n && tolower(*h2) == tolower(*n)) {
            h2++;
            n++;
        }
        if (!*n) return (char *)h;
        h++;
    }
    return nullptr;
}

size_t my_strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

void *my_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

void *my_memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}

int my_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}
