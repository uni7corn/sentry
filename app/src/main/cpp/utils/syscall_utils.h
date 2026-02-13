#ifndef SYSCALL_UTILS_H
#define SYSCALL_UTILS_H

#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// Direct syscall wrappers to bypass libc hooks
ssize_t my_read(int fd, void *buf, size_t count);
ssize_t my_write(int fd, const void *buf, size_t count);
int my_open(const char *pathname, int flags, mode_t mode);
int my_close(int fd);

/** 先尝试 syscall 打开，失败时回退到 libc open，提高兼容性。*out_used_syscall=1 表示用 syscall 打开，后续读用 read_with_fallback。 */
int open_with_fallback(const char *pathname, int flags, mode_t mode, int *out_used_syscall);
/** 根据 open_with_fallback 的 out_used_syscall 选择 my_read 或 libc read，与 open_with_fallback 配套使用。 */
ssize_t read_with_fallback(int fd, void *buf, size_t count, int used_syscall);
int my_access(const char *pathname, int mode);
pid_t my_getpid(void);
int my_kill(pid_t pid, int sig);
int my_gettid(void);
int my_tgkill(pid_t pid, int tid, int sig);
ssize_t my_lseek(int fd, off_t offset, int whence);

// Socket syscalls (bypass libc hooks for connect/socket/close/send/recv)
int my_socket(int domain, int type, int protocol);
int my_connect(int sockfd, const void *addr, unsigned int addrlen);
int my_setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);

// String operations
char *my_strcpy(char *dest, const char *src);
char *my_strncpy(char *dest, const char *src, size_t n);
int my_strcmp(const char *s1, const char *s2);
int my_strncmp(const char *s1, const char *s2, size_t n);
char *my_strstr(const char *haystack, const char *needle);
char *my_strcasestr(const char *haystack, const char *needle);
size_t my_strlen(const char *s);
void *my_memcpy(void *dest, const void *src, size_t n);
void *my_memset(void *s, int c, size_t n);
int my_memcmp(const void *s1, const void *s2, size_t n);

#ifdef __cplusplus
}
#endif

#endif // SYSCALL_UTILS_H
