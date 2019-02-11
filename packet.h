/* packet.h: declarations for header structures used for
 *           parameter-passing, and operation constants.
 * author: Senyu Tong
 * id: senyut
 */

#define OP_OPEN 1
#define OP_CLOSE 2
#define OP_WRITE 3
#define OP_READ 4
#define OP_LSEEK 5
#define OP_UNLINK 6
#define OP_STAT 7
#define OP_GETDIREN 8
#define OP_GETDIRTREE 9
#define OP_FREEDIR 10
#define TREE_SUCCESS 11
#define TREE_FAIL 12
#define ERROR -1
#define MAX_TREE_SIZE 100000

/* send_msg: do exactly the same as send, but automatically check err */
void send_msg(int sockfd, void *buf, size_t nbytes, int flag) {
    int sv = send(sockfd, buf, nbytes, flag);
    if (sv < 0) err(1, 0);
}

/* recv_msg: do exactly the same as recv, but automatically check err */
void recv_msg(int sockfd, void *buf, size_t nbytes, int flag) {
    int rv = recv(sockfd, buf, nbytes, flag);
    if (rv < 0) err(1, 0);
}

/* General request header
 * op_number | parameter-length | operation header
 */
typedef struct {
    int op;
    size_t para_len;
    /* we don't know how big the operation header is, declaring
     * it as an array of size 0 allows computing its starting address using
     * pointer notation.
     */
    char op_head[0];
} request_header_t;

/* open opeartion request header
 * flag | mode | filename-length | filename
 */
typedef struct {
    int flag;
    mode_t mode;
    size_t path_len;
    char path[0];
} op_open_header_t;

/* close operation request header
 * just the file descriptor, total 4 bytes
 */
typedef struct{
    int fd;
} op_close_header_t;

/* write operation request header
 * fd | buffer size | buffer
 */
typedef struct {
    int fd;
    size_t buf_len;
    char buf[0];
} op_write_header_t;

/* read operation request header
 * fd | buf_size, total 16 bytes
 */
typedef struct {
    int fd;
    size_t buf_size;
} op_read_header_t;

/* lseek operation request header
 * fd | whence | offset, total 16 bytes */
typedef struct {
    int fd;
    int whence;
    off_t offset;
} op_lseek_header_t;

/* xstat operation request header
 * ver | path_len | path_name
 */
typedef struct {
    int ver;
    size_t path_len;
    char path[0];
} op_stat_header_t;

/* unlink operation request header
 * path_len | path_name
 */
typedef struct {
    size_t path_len;
    char path[0];
} op_unlink_header_t;

/* getdirentreis request header
 * fd | nbytes | basep
 */
typedef struct {
    int fd;
    size_t buf_size;
    off_t basep;
} op_getdirent_header_t;

/* getdirtree request header
 * pathlen | pathname
 */
typedef struct {
    size_t path_len;
    char name[0];
} op_tree_header_t;

