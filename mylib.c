/* mylib.c: interpose library for the client side to make RPC calls
 * author: Senyu Tong
 * andrew id: senyut
 * 15-440 Project 1
 * 2019 - 02 - 08
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include "packet.h"
#include "../include/dirtree.h"

#define THRESHOLD 100000  // to differentiate loacl and rpc fds

int connect_serv();
int (*orig_open)(const char *pathname, int flags, ...);
int (*orig_close)(int filds);
ssize_t (*orig_read)(int filds, void *buf, size_t nbyte);
ssize_t (*orig_write)(int filds, const void *buf, size_t nbyte);
off_t (*orig_lseek)(int filds, off_t offset, int whence);
int (*orig_unlink)(const char *pathname);
int (*orig___xstat)(int ver, const char *pat, struct stat *buf);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes, off_t *basep);
struct dirtreenode* (*orig_getdirtree) (const char *path);
void (*orig_freedirtree) (struct dirtreenode* dirtree);
// Helper functions
struct dirtreenode *read_tree(void *buf, int *offset);
void freedt(struct dirtreenode *dt);
// Checker for file descriptor
bool check(int fd);

// gloable sockfd for send and recv
static int sockfd = -1;

/* connect_serv: Connect to a TCP server
 *               code adapted from sample clent.c
 */
int connect_serv() {
    char *serverip;
    char *serverport;
    unsigned short port;
    int sockfd, rv;
    struct sockaddr_in srv;

    // Get environment variable indicating the ip address of the server
    serverip = getenv("server15440");
    if (!serverip) serverip = "127.0.0.1";

    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (!serverport) serverport = "15440";
    port = (unsigned short)atoi(serverport);

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // TCP/IP socket
    if (sockfd < 0) err(1, 0);                // In case of error

    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr(serverip);
    srv.sin_port = htons(port);

    // actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv,
                sizeof(struct sockaddr));
    if (rv < 0) err(1, 0);

    // return socket
    return sockfd;
}

/* check_fd: check if the file descriptor is called by system
 *           or by lib to prevent bad descriptor error
 * input: filedescriptor
 * output: 0 for loacl, 1 for RPC
 * DEFAULT ACTION if fd is loacl: run orig__operation.
 */
bool check(int fd) {
    if (fd < THRESHOLD) return false;
    return true;
}

/* open: to open (or create) a file
 *  send_msging struct: flag | mode | filename_length | filename
 *  recieving struct: fd | errno */
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}

    /* pack the info into packet struct */
    size_t path_len = strlen(pathname) + 1;
    size_t para_len = sizeof(op_open_header_t) + path_len;
    /* int for op_type, size_t for parameter length,
     * 4 bytes padding and the para_len itself */
    size_t request_len = sizeof(request_header_t) + para_len;
    request_header_t *to_request = (request_header_t *)malloc(request_len);
    to_request->op = OP_OPEN;
    to_request->para_len = para_len;
    /* put the actual request header in the
     * op_head part of the generic header */
    op_open_header_t *open_request = (op_open_header_t *)to_request->op_head;
    open_request->flag = flags;
    open_request->mode = m;
    open_request->path_len = path_len;
    char *filename = (char *)open_request->path;
    memcpy(filename, pathname, path_len);
    fprintf(stderr, "client sent info: \n");
    fprintf(stderr, "flag: %d\n", open_request->flag);
    fprintf(stderr, "mode: %d\n", open_request->mode);
    fprintf(stderr, "name: %s\n", open_request->path);

    /* send_msg the packet to the server */
    send_msg(sockfd, (void *)to_request, request_len, 0);
    fprintf(stderr, "client sent %d bytes\n",(int)request_len);
    free(to_request);

    /* recieving returning packet from the server */
    int rec_size = sizeof(int) + sizeof(errno);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, 0);
    int fd;
    memcpy(&fd, to_recv, sizeof(int));
    memcpy(&errno, to_recv + sizeof(int), sizeof(errno));

    /* to differentiate our file descriptor, add an offset */
    if (fd != ERROR) fd += THRESHOLD;
    free(to_recv);

    return fd;
}

/* close: to close a file
 *   send_msg struct: fd
 *   recv_msg struct: fd | errno */
int close(int fd) {
    /* check if fd is local */
    if (!check(fd)) return orig_close(fd);
    fd -= THRESHOLD;

    /* pack the info */
    size_t para_len = sizeof(op_close_header_t);
    size_t request_len = sizeof(request_header_t) + para_len;
    request_header_t *to_request = (request_header_t *)malloc(request_len);
    to_request->op = OP_CLOSE;
    to_request->para_len = para_len;
    op_close_header_t *close_request = (op_close_header_t *)to_request->op_head;
    close_request->fd = fd;

    /* send_msg the message */
    send_msg(sockfd, (void *)to_request, request_len, 0);
    free(to_request);

    /* recieve msg from the server */
    int rec_size = sizeof(int) + sizeof(errno);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, 0);
    int s_fd;
    memcpy(&s_fd, to_recv, sizeof(int));
    memcpy(&errno, to_recv + sizeof(int), sizeof(errno));
    free(to_recv);
    return s_fd;
}

/* read: to read from a file descriptor
 *   send_msg struct: fd | number_of_bytes
 *   recv_msg struct: nbyte | errno | read_buffer */
ssize_t read(int fd, void *buf, size_t nbyte) {
    /* check if fd is local */
    if (!check(fd)) return orig_close(fd);
    fd -= THRESHOLD;

    /* pack the info */
    /* we don't need to send_msg the buffer, let the server handle th job */
    size_t para_len = sizeof(op_read_header_t);
    size_t req_len = para_len + sizeof(request_header_t);
    request_header_t *to_request = (request_header_t *)malloc(req_len);
    to_request->op = OP_READ;
    to_request->para_len = para_len;
    op_read_header_t *read_req = (op_read_header_t *)to_request->op_head;
    read_req->fd = fd;
    read_req->buf_size = nbyte;
    fprintf(stderr, "file_byte: %zd\n", read_req->buf_size);

    /* send_msg message */
    send_msg(sockfd, (void *)to_request, req_len, 0);
    free(to_request);

    /* recieve message */
    int rec_size = sizeof(size_t) + sizeof(errno) + nbyte;
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, MSG_WAITALL);
    ssize_t read_count;
    memcpy(&read_count, to_recv, sizeof(ssize_t));
    memcpy(&errno, to_recv + sizeof(ssize_t), sizeof(errno));
    /* load the info being read into the buf */
    memcpy(buf, to_recv + sizeof(ssize_t) + sizeof(errno), nbyte);
    free(to_recv);

    return read_count;
}

/* write: write to fd
 *   send_msg struct: fd | buffer length | buffer
 *   recv_msg struct: nbyte | errno */
ssize_t write(int fd, const void *buf, size_t nbyte) {
    /* check if fd is local */
    if (!check(fd)) return orig_write(fd, buf, nbyte);
    fd -= THRESHOLD;

    /* pack the info */
    size_t para_len = sizeof(op_write_header_t) + nbyte;
    size_t req_len = para_len + sizeof(request_header_t) ;
    request_header_t *to_request = (request_header_t *)malloc(req_len);
    to_request->op = OP_WRITE;
    to_request->para_len = para_len;
    op_write_header_t *write_req = (op_write_header_t *)to_request->op_head;
    write_req->fd = fd;
    write_req->buf_len = nbyte;
    char *write_buf = (char *)write_req->buf;
    memcpy(write_buf, buf, nbyte);

    /* send_msg message */
    send_msg(sockfd, (void *)to_request, req_len, 0);
    free(to_request);

    /* recieve from the server */
    int rec_size = sizeof(ssize_t) + sizeof(errno);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, 0);
    ssize_t ret;
    memcpy(&ret, to_recv, sizeof(ssize_t));
    memcpy(&errno, to_recv + sizeof(ssize_t), sizeof(errno));
    free(to_recv);
    return ret;
}

/* lseek: repositioning file offset
 *   send_msg struct: fd | offset | whence
 *   recv_msg struct: offset | errno */
off_t lseek(int fd, off_t offset, int whence) {
    /* check if fd is local */
    if (!check(fd)) return orig_close(fd);
    fd -= THRESHOLD;

    /* pack the info */
    size_t para_len = sizeof(op_lseek_header_t);
    size_t request_len = sizeof(request_header_t) + para_len;
    request_header_t *to_request = (request_header_t *)malloc(request_len);
    to_request->op = OP_LSEEK;
    to_request->para_len = para_len;
    op_lseek_header_t *lseek_req = (op_lseek_header_t *)to_request->op_head;
    lseek_req->fd = fd;
    lseek_req->whence = whence;
    lseek_req->offset = offset;

    /* send_msg the message */
    send_msg(sockfd, (void *)to_request, request_len, 0);
    free(to_request);

    /* recieve msg from the server */
    int rec_size = sizeof(off_t) + sizeof(errno);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, MSG_WAITALL);
    off_t r_offset;
    memcpy(&r_offset, to_recv, sizeof(off_t));
    memcpy(&errno, to_recv + sizeof(off_t), sizeof(errno));
    fprintf(stderr, "get: %d bytes; answer: %jd\n", rec_size, r_offset);
    free(to_recv);
    return r_offset;
}

/* __xstat: provide inode information
 *   send_msg struct: ver | path_name
 *   recv_msg struct: ret_int | errno | stat strut */
int __xstat(int ver, const char *pathname, struct stat *buf) {
    /* pack the info into packet struct */
    size_t path_len = strlen(pathname) + 1;
    size_t para_len = sizeof(op_stat_header_t) + path_len;
    size_t request_len = sizeof(request_header_t) + para_len;
    request_header_t *to_request = (request_header_t *)malloc(request_len);
    to_request->op = OP_STAT;
    to_request->para_len = para_len;
    /* put the actual request header in the
     * op_head part of the generic header */
    op_stat_header_t *stat_request = (op_stat_header_t *)to_request->op_head;
    stat_request->ver = ver;
    stat_request->path_len = path_len;
    char *filename = (char *)stat_request->path;
    memcpy(filename, pathname, path_len);

    /* send_msg the packet to the server */
    send_msg(sockfd, (void *)to_request, request_len, 0);
    free(to_request);

    /* recieving returning packet from the server */
    int rec_size = sizeof(ver) + sizeof(errno) + sizeof(struct stat);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, 0);
    int ret;
    memcpy(&ret, to_recv, sizeof(int));
    memcpy(&errno, to_recv + sizeof(int), sizeof(errno));
    memcpy(buf, to_recv + sizeof(int) + sizeof(errno), sizeof(struct stat));
    free(to_recv);

    return ret;
}

/* unlink: delete a name and possibly a file it refers to
 *   send_msg struct: simply a string
 *   recv_msg struct: retval | errno */
int unlink(const char *pathname) {
    /* pack the info into packet struct */
    size_t path_len = strlen(pathname) + 1;
    size_t para_len = sizeof(op_unlink_header_t) + path_len;
    size_t request_len = sizeof(request_header_t) + para_len;
    request_header_t *to_request = (request_header_t *)malloc(request_len);
    to_request->op = OP_UNLINK;
    to_request->para_len = para_len;
    op_unlink_header_t *unlink_req =
        (op_unlink_header_t *)to_request->op_head;
    unlink_req->path_len = path_len;
    char *filename = (char *)unlink_req->path;
    memcpy(filename, pathname, path_len);

    /* send_msg the packet to the server */
    send_msg(sockfd, (void *)to_request, request_len, 0);
    free(to_request);

    /* recieving returning packet from the server */
    int ret;
    int rec_size = sizeof(ret) + sizeof(errno) + sizeof(struct stat);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, 0);
    memcpy(&ret, to_recv, sizeof(int));
    memcpy(&errno, to_recv + sizeof(int), sizeof(errno));
    free(to_recv);

    return ret;
}


/* getdirentries: get directory entries
 *   send_msg struct: fd | nbyte | basep
 *   recv_msg struct: nbyte | errno | buf_materials | new_basep */
ssize_t getdirentries(int fd, char *buf, size_t nbytes, off_t *basep) {
    /* check if fd is local */
    if (!check(fd)) return orig_close(fd);
    fd -= THRESHOLD;

    /* pack the info */
    /* we don't need to send_msg the buffer, let the server handle th job */
    size_t para_len = sizeof(op_getdirent_header_t);
    size_t req_len = para_len + sizeof(request_header_t);
    request_header_t *to_request = (request_header_t *)malloc(req_len);
    to_request->op = OP_GETDIREN;
    to_request->para_len = para_len;
    op_getdirent_header_t *diren_req =
        (op_getdirent_header_t *)to_request->op_head;
    diren_req->fd = fd;
    diren_req->buf_size = nbytes;
    diren_req->basep = *basep;

    /* send_msg message */
    send_msg(sockfd, (void *)to_request, req_len, 0);
    free(to_request);

    /* recieve message */
    int rec_size = sizeof(size_t) + sizeof(errno) + sizeof(off_t);
    void *to_recv = malloc(rec_size);
    recv_msg(sockfd, to_recv, rec_size, MSG_WAITALL);
    ssize_t count;
    memcpy(&count, to_recv, sizeof(count));
    memcpy(&errno, to_recv + sizeof(count), sizeof(errno));
    memcpy(basep, to_recv + sizeof(count) +
            sizeof(errno), sizeof(off_t));
    /* wirte on buf only if return succesfully */
    if (count != ERROR)
        recv_msg(sockfd, buf, nbytes, MSG_WAITALL);
    fprintf(stderr, "recieved count: %zd\n", count);
    fprintf(stderr, "new_off %jd\n", *basep);
    free(to_recv);

    return count;
}

/* getdirtree: recusively descend through directory
 *   send_msg struct: path_len | path_name
 *   recv_msg struct: recursively recieve each sub_structure
 */
struct dirtreenode* getdirtree (const char *path) {
    /* pack the info into packet struct */
    size_t path_len = strlen(path) + 1;
    size_t para_len = sizeof(op_tree_header_t) + path_len;
    size_t request_len = sizeof(request_header_t) + para_len;
    request_header_t *to_request = (request_header_t *)malloc(request_len);
    to_request->op = OP_GETDIRTREE;
    to_request->para_len = para_len;
    op_tree_header_t *tree_req =
        (op_tree_header_t *)to_request->op_head;
    tree_req->path_len = path_len;
    char *filename = (char *)tree_req->name;
    memcpy(filename, path, path_len);

    /* send_msg the packet to the server */
    send_msg(sockfd, (void *)to_request, request_len, 0);
    free(to_request);

    /* recieving first_touch packet from the server */
    int status;
    int size;
    void *initbuf = malloc(sizeof(status) + sizeof(size));
    recv_msg(sockfd, initbuf, sizeof(status) + sizeof(size), 0);
    memcpy(&status, initbuf, sizeof(status));
    if (status == TREE_FAIL) {
        memcpy(&errno, initbuf + sizeof(status), sizeof(errno));
        free(initbuf);
        return NULL;
    }
    else {
        memcpy(&size, initbuf + sizeof(status), sizeof(size));
        free(initbuf);
        /* start recieving the full buf */
        void *fulltree = malloc(size);
        recv_msg(sockfd, fulltree, size, MSG_WAITALL);
        int offset = 0;
        struct dirtreenode *ret = read_tree(fulltree, &offset);
        free(fulltree);
        return ret;
    }
}

/* read_tree: unpack the information in the buf sent by the server
 *      buffer block format: (int)name_len | (int)num_sub | (str)name
 *      input: buffer, and where should we read on
 */
struct dirtreenode *read_tree(void *buf, int *offset) {
    struct dirtreenode *ret = malloc(sizeof(struct dirtreenode));
    int name_len = 0;
    int num_sub = 0;
    buf += *offset;
    memcpy(&name_len, buf, sizeof(int));
    memcpy(&num_sub, buf + sizeof(int), sizeof(int));
    ret->name = malloc(name_len);
    memcpy(ret->name, buf + sizeof(int) + sizeof(int), name_len);
    ret->num_subdirs = num_sub;
    /* expecting subdirs trees */
    ret->subdirs = malloc(sizeof(struct dirtreenode*) * ret->num_subdirs);
    buf -= *offset;
    *offset += sizeof(int) + sizeof(int) + name_len;
    for (int i = 0; i < ret->num_subdirs; i++)
        ret->subdirs[i] = read_tree(buf, offset);
    return ret;
}

/* freedt: recursively free the structure dt */
void freedt (struct dirtreenode* dt) {
    for (int i = 0; i < dt->num_subdirs; i++)
        freedt(dt->subdirs[i]);
    free(dt->name);
    free(dt->subdirs);
    free(dt);
}

/* freedirtree: NOT an RPC call */
void freedirtree (struct dirtreenode* dirtree) {
    freedt(dirtree);
}

// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT, "close");
    orig_read = dlsym(RTLD_NEXT, "read");
    orig_write = dlsym(RTLD_NEXT, "write");
    orig_lseek = dlsym(RTLD_NEXT, "lseek");
    orig_unlink = dlsym(RTLD_NEXT, "unlink");
    orig___xstat = dlsym(RTLD_NEXT, "__xstat");
    orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
    orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
    orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
    sockfd = connect_serv();
}

// automatically called when program ends
void _fini(void) {
    orig_close(sockfd);
}

