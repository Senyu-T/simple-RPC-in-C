/* server.c: server that provides remote file services
 * author: Senyu Tong
 * andrew id: senyut
 * 15-440 Project 1
 * 2019 - 02 - 08
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <dirent.h>
#include "packet.h"
#include "../include/dirtree.h"

void op_open(int sessfd, op_open_header_t *req);
void op_close(int sessfd, op_close_header_t *req);
void op_write(int sessfd, op_write_header_t *req);
void op_read(int sessfd, op_read_header_t *req);
void op_lseek(int sessfd, op_lseek_header_t *req);
void op_stat(int sessfd, op_stat_header_t *req);
void op_unlink(int sessfd, op_unlink_header_t *req);
void op_getdiren(int sessfd, op_getdirent_header_t *req);
void op_getdirtree(int sessfd, op_tree_header_t *req);
// the helper function for sending reply structures of getdirtree
void construct_tree(void *buffer, struct dirtreenode *root,
                    int *buf_offset, int *size);

int main(int argc, char**argv) {
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;

	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
    else port = 15440;

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error

	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);

	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);

	// main server loop, handle clients one at a time
	while(1) {
		// wait for next client, get session socket
		sa_size = sizeof(struct sockaddr_in);
		sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
		if (sessfd<0) err(1,0);
        pid_t pid = fork();
        if (pid == 0) {
            close(sockfd);
            size_t header_size = sizeof(request_header_t);
            // get messages and send_msg replies to this client, until it goes away
            while (1) {
                void *buf = malloc(header_size);
                recv_msg(sessfd, buf, header_size, MSG_WAITALL);
                /* we have recieved op and para_len */
                request_header_t *task = (request_header_t *)buf;
                int operation = task->op;
                size_t para_len = task->para_len;
                /* we then recieve the operation header */
                void *request = malloc(para_len);
                switch(operation) {
                    case OP_OPEN:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_open(sessfd, (op_open_header_t *)request);
                        break;
                    case OP_WRITE:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_write(sessfd, (op_write_header_t *)request);
                        break;
                    case OP_CLOSE:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_close(sessfd, (op_close_header_t *)request);
                        break;
                    case OP_READ:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_read(sessfd, (op_read_header_t *)request);
                        break;
                    case OP_LSEEK:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_lseek(sessfd, (op_lseek_header_t *)request);
                        break;
                    case OP_STAT:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_stat(sessfd, (op_stat_header_t *)request);
                        break;
                    case OP_UNLINK:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_unlink(sessfd, (op_unlink_header_t *)request);
                        break;
                    case OP_GETDIREN:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_getdiren(sessfd, (op_getdirent_header_t *)request);
                        break;
                    case OP_GETDIRTREE:
                        recv_msg(sessfd, request, para_len, MSG_WAITALL);
                        op_getdirtree(sessfd, (op_tree_header_t *)request);
                        break;
                }
                free(task);
                free(request);
            }
	    }
        else {
            close(sessfd);
        }
    }
	close(sockfd);
	return 0;
}

void op_open(int sessfd, op_open_header_t *request) {
    /* extract information from the header type */
    int flag = request->flag;
    mode_t mode = request->mode;
    size_t name_len = request->path_len;
    char *filepath = malloc(name_len);
    memcpy(filepath, request->path, name_len);
    fprintf(stderr, "server recieved info: \n");
    fprintf(stderr, "flag: %d\n", flag);
    fprintf(stderr, "mode: %d\n", mode);
    fprintf(stderr, "name: %s\n", filepath);

    /* do the actual work */
    int fd = open(filepath, flag, mode);

    /* pack the return info by
     * (int) fd | errno */
    void *replybuf = malloc(sizeof(fd) + sizeof(errno));
    memcpy(replybuf, &fd, sizeof(fd));
    memcpy(replybuf + sizeof(fd), &errno, sizeof(errno));

    /* send_msg the replying packet to the client */
    send_msg(sessfd, replybuf, sizeof(fd) + sizeof(errno), 0);
    free(filepath);
    free(replybuf);
}

void op_close(int sessfd, op_close_header_t *request) {
    /* extract info and perform the work*/
    int r_fd = request->fd;
    int fd = close(r_fd);

    /* pack and send_msg reply */
    void *replybuf = malloc(sizeof(fd) + sizeof(errno));
    memcpy(replybuf, &fd, sizeof(fd));
    memcpy(replybuf + sizeof(fd), &errno, sizeof(errno));
    send_msg(sessfd, replybuf, sizeof(fd) + sizeof(errno), 0);
    free(replybuf);
}

void op_write(int sessfd, op_write_header_t *request) {
    /* extract info an perform the work */
    int r_fd = request->fd;
    size_t buf_len = request->buf_len;
    char *write_buf = malloc(buf_len);
    memcpy(write_buf, request->buf, buf_len);
    ssize_t ret = write(r_fd, write_buf, buf_len);
    free(write_buf);

    /* pack and reply */
    void *replybuf = malloc(sizeof(ret) + sizeof(errno));
    memcpy(replybuf, &ret, sizeof(ret));
    memcpy(replybuf + sizeof(ret), &errno, sizeof(errno));
    send_msg(sessfd, replybuf, sizeof(ret) + sizeof(errno), 0);
    free(replybuf);
}

void op_read(int sessfd, op_read_header_t *request) {
    /* extract info */
    int r_fd = request->fd;
    size_t buf_len = request->buf_size;
    char *read_buf = malloc(buf_len);

    /* perform the work */
    ssize_t ret = read(r_fd, read_buf, buf_len);

    /* pack information */
    int reply_size = sizeof(ret) + sizeof(errno) + buf_len;
    void *replybuf = malloc(reply_size);
    memcpy(replybuf, &ret, sizeof(ret));
    memcpy(replybuf + sizeof(ret), &errno, sizeof(errno));
    memcpy(replybuf + sizeof(errno) + sizeof(ret), read_buf, buf_len);
    fprintf(stderr, "server_read: %zd\n", ret);

    /* reply */
    send_msg(sessfd, replybuf, reply_size, 0);
    free(read_buf);
    free(replybuf);
}

void op_lseek(int sessfd, op_lseek_header_t *request) {
    /* extract info */
    int r_fd = request->fd;
    int r_whence = request->whence;
    off_t r_off = request->offset;

    /* perform the work */
    off_t ret = lseek(r_fd, r_off, r_whence);
    fprintf(stderr, "trueanswer: %jd\n", ret);

    /* pack info */
    int reply_size = sizeof(ret) + sizeof(errno);
    void *replybuf = malloc(reply_size);
    memcpy(replybuf, &ret, sizeof(ret));
    memcpy(replybuf + sizeof(ret), &errno, sizeof(errno));

    /* reply */
    send_msg(sessfd, replybuf, reply_size, 0);
    free(replybuf);
}

void op_stat(int sessfd, op_stat_header_t *request) {
    /* extract info */
    int r_ver = request->ver;
    size_t name_len = request->path_len;
    char *filepath = malloc(name_len);
    memcpy(filepath, request->path, name_len);

    /* perform the work */
    struct stat reply;
    int ret = __xstat(r_ver, filepath, &reply);

    /* pack info */
    int reply_size = sizeof(ret) + sizeof(errno) + sizeof(struct stat);
    void *replybuf = malloc(reply_size);
    memcpy(replybuf, &ret, sizeof(ret));
    memcpy(replybuf + sizeof(ret), &errno, sizeof(errno));
    memcpy(replybuf + sizeof(ret) + sizeof(errno), &reply, sizeof(struct stat));

    /* reply */
    send_msg(sessfd, replybuf, reply_size, 0);
    free(replybuf);
}

void op_unlink(int sessfd, op_unlink_header_t *request) {
    /* extract info */
    size_t name_len = request->path_len;
    char *filepath = malloc(name_len);
    memcpy(filepath, request->path, name_len);

    /* perform the work */
    int ret = unlink(filepath);
    free(filepath);

    /* pack info */
    int reply_size = sizeof(ret) + sizeof(errno);
    void *replybuf = malloc(reply_size);
    memcpy(replybuf, &ret, sizeof(ret));
    memcpy(replybuf + sizeof(ret), &errno, sizeof(errno));

    /* reply */
    send_msg(sessfd, replybuf, reply_size, 0);
    free(replybuf);
}

void op_getdiren(int sessfd, op_getdirent_header_t *request) {
    /* extract info */
    int r_fd = request->fd;
    size_t buf_len = request->buf_size;
    off_t base = request->basep;
    char *buf = malloc(buf_len);

    /* perform the work */
    ssize_t ret = getdirentries(r_fd, buf, buf_len, &base);

    /* pack information, exclude the actural buf first */
    int reply_size = sizeof(ret) + sizeof(errno) + sizeof(base);
    void *replybuf = malloc(reply_size);
    memcpy(replybuf, &ret, sizeof(ret));
    memcpy(replybuf + sizeof(ret), &errno, sizeof(errno));
    memcpy(replybuf + reply_size - sizeof(base), &base, sizeof(base));
    fprintf(stderr, "realnewoff: %jd\n", base);

    /* send the message, but only send buf when ret not ERROR */
    send_msg(sessfd, replybuf, reply_size, 0);
    if (ret != ERROR)
        send_msg(sessfd, buf, buf_len, 0);

    /* reply */
    free(buf);
    free(replybuf);
}

void op_getdirtree(int sessfd, op_tree_header_t *request) {
    /* extract info */
    size_t name_len = request->path_len;
    char *filepath = malloc(name_len);
    memcpy(filepath, request->name, name_len);

    /* perform the work */
    struct dirtreenode *root = getdirtree(filepath);
    free(filepath);

    /* write a tree into buffer in name_len | num_subdir | name */
    /* build a buffer with size MAX_TREE_SIZE, if exceeds, realloc */
    int status;
    void *buffer = malloc(MAX_TREE_SIZE);
    int size = MAX_TREE_SIZE;
    int buf_offset = 0;
    /* first touch is to send status, if fail then errno, o.w nbytes of buf */
    int first_size = sizeof(status) + sizeof(size);
    void *first_touch = malloc(first_size);
    /* if error occurs and ret is null, set errno */
    if (root == NULL) {
        status = TREE_FAIL;
        /* set the stat to fail, and set errno but nothing else */
        memcpy(first_touch, &status, sizeof(status));
        memcpy(first_touch + sizeof(status), &errno, sizeof(errno));
        /* send back the msg */
        send_msg(sessfd, first_touch, first_size, 0);
    }
    /* recursively expand the structure and pack info */
    else {
        status = TREE_SUCCESS;
        /* write the whole tree struct into this giant buffer */
        construct_tree(buffer, root, &buf_offset, &size);
        /* send first the status and nbytes of the giant buffer */
        memcpy(first_touch, &status, sizeof(status));
        memcpy(first_touch + sizeof(status), &size, sizeof(int));
        send_msg(sessfd, first_touch, first_size, 0);
        /* send the actual buffer */
        send_msg(sessfd, buffer, size, 0);
    }
    free(first_touch);
    free(buffer);
    freedirtree(root);
}

/* construct_tree: given a whole tree, write the full info into the buffer.
 *      if the size is larger than previous allocated bytes, then double it
 *      buf_offset indicates where should we write on to the buf
 */
void construct_tree(void *buffer, struct dirtreenode *root,
                    int *buf_offset, int *size) {
    int root_name_len = strlen(root->name) + 1;
    int root_numdir = root->num_subdirs;
    /* find the actual offset of buffer to be written on */
    int old_offset = *buf_offset;
    buffer += *buf_offset;
    /* find the next region to be written on for next sub struct */
    *buf_offset += root_name_len +
                   sizeof(root_numdir) + sizeof(root_name_len);
    /* if memory space not enough, expand it to be twice as large */
    if (*buf_offset >= *size) {
        *size = *size * 2;
        buffer = realloc(buffer, *size);
        buffer += old_offset;
    }

    /* write name and numdir to the buffer */
    memcpy(buffer, &root_name_len, sizeof(root_name_len));
    memcpy(buffer + sizeof(int), &root_numdir, sizeof(int));
    memcpy(buffer + sizeof(int) + sizeof(int), root->name, root_name_len);

    /* for each subdir, write to the buffer */
    buffer -= old_offset;
    for (int i = 0; i < root_numdir; i++) {
        construct_tree(buffer, root->subdirs[i], buf_offset, size);
    }
}
