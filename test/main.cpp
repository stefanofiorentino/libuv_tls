#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uv.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

#include "include/json_utils.hpp"
#include "include/all_dto.hpp"

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct tls_uv_connection_state tls_uv_connection_state_t;

typedef struct {
    tls_uv_connection_state_t* (*create_connection)(uv_tcp_t* connection);
    int (*connection_established)(tls_uv_connection_state_t* connection);
    void (*connection_closed)(tls_uv_connection_state_t* connection, int status);
    int (*read)(tls_uv_connection_state_t* connection, void* buf, ssize_t nread);
} connection_handler_t;

typedef struct {
    SSL_CTX *ctx;
    uv_loop_t* loop;
    connection_handler_t protocol;
    tls_uv_connection_state_t* pending_writes;
} tls_uv_server_state_t;


typedef struct tls_uv_connection_state {
    tls_uv_server_state_t* server;
    uv_tcp_t* handle;
    SSL *ssl;
    BIO *read, *write;
    struct {
        tls_uv_connection_state_t** prev_holder;
        tls_uv_connection_state_t* next;
        int in_queue;
        size_t pending_writes_count;
        uv_buf_t* pending_writes_buffer;
    } pending;
} tls_uv_connection_state_t;

int get_generic_error(tls_uv_connection_state_t *connection);

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    std::puts(__PRETTY_FUNCTION__);
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void report_connection_failure(int status) {
    std::puts(__PRETTY_FUNCTION__);
    fprintf(stderr, "New connection error %s\n", uv_strerror(status));
}

void remove_connection_from_queue(tls_uv_connection_state_t* cur) {
    std::puts(__PRETTY_FUNCTION__);
    if (cur->pending.pending_writes_buffer != NULL) {
        free(cur->pending.pending_writes_buffer);
    }
    if (cur->pending.prev_holder != NULL) {
        *cur->pending.prev_holder = cur->pending.next;
    }

    memset(&cur->pending, 0, sizeof(cur->pending));
}

void abort_connection_on_error(tls_uv_connection_state_t* state) {
    std::puts(__PRETTY_FUNCTION__);
    uv_close((uv_handle_t*)state->handle, NULL);
    SSL_free(state->ssl);
    // implicitly freed by SSL_free
    //BIO_free(state->read);
    //BIO_free(state->write);
    remove_connection_from_queue(state);
    free(state);
}


void maybe_flush_ssl(tls_uv_connection_state_t* state) {
    std::puts(__PRETTY_FUNCTION__);
    if (state->pending.in_queue)
        return;
    if (BIO_pending(state->write) == 0 && state->pending.pending_writes_count > 0)
        return;
    state->pending.next = state->server->pending_writes;
    if (state->pending.next != NULL) {
        state->pending.next->pending.prev_holder = &state->pending.next;
    }
    state->pending.prev_holder = &state->server->pending_writes;
    state->pending.in_queue = 1;

    state->server->pending_writes = state;
}

void handle_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    std::puts(__PRETTY_FUNCTION__);
    auto* state = static_cast<tls_uv_connection_state_t *>(client->data);

    BIO_write(state->read, buf->base, nread);
    while (1)
    {
        int rc = SSL_read(state->ssl, buf->base, buf->len);
        std::printf("rc: %d\n", rc);
        if (rc <= 0) {
            rc = SSL_get_error(state->ssl, rc);
            if (rc != SSL_ERROR_WANT_READ) {
                state->server->protocol.connection_closed(state, rc);
                abort_connection_on_error(state);
                break;
            }
            maybe_flush_ssl(state);
            // need to read more, we'll let libuv handle this
            break;
        }
        if (state->server->protocol.read(state, buf->base, rc) == 0) {
            // protocol asked to close the socket
            abort_connection_on_error(state);
            break;
        }
    }

    if (buf->base)
        free(buf->base);
}

void complete_write(uv_write_t* req, int status) {
    std::puts(__PRETTY_FUNCTION__);
    write_req_t* wr;
    wr = (write_req_t*) req;

    auto* state = static_cast<tls_uv_connection_state_t *>(wr->req.data);

    char * const str = static_cast<char *const>(wr->buf.base);
    if (std::string(str).find("{}") != std::string::npos)
    {
        if (!uv_is_closing(reinterpret_cast<const uv_handle_t *>(state->handle)))
        {
            uv_close(reinterpret_cast<uv_handle_t *>(state->handle), reinterpret_cast<uv_close_cb>(free));
        }
    }

    if (status < 0) {
        state->server->protocol.connection_closed(state, status);
        abort_connection_on_error(state);
    }

    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

void flush_ssl_buffer(tls_uv_connection_state_t* cur) {
    std::puts(__PRETTY_FUNCTION__);
    int rc = BIO_pending(cur->write);
    if (rc > 0) {
        write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
        wr->buf = uv_buf_init((char *)malloc(rc), rc);
        BIO_read(cur->write, wr->buf.base, rc);
        wr->req.data = cur;
        uv_write(&wr->req, (uv_stream_t*)cur->handle, &wr->buf, 1, complete_write);
    }
}


void try_flush_ssl_state(uv_handle_t * handle) {
    std::puts(__PRETTY_FUNCTION__);
    auto* server_state = static_cast<tls_uv_server_state_t *>(handle->data);
    tls_uv_connection_state_t** head = &server_state->pending_writes;

    while (*head != NULL) {
        tls_uv_connection_state_t* cur = *head;

        flush_ssl_buffer(cur);

        if (cur->pending.pending_writes_count == 0) {
            remove_connection_from_queue(cur);
            continue;
        }

        // here we have pending writes to deal with, so we'll try stuffing them
        // into the SSL buffer
        int used = 0;
        for (size_t i = 0; i < cur->pending.pending_writes_count; i++)
        {
            int rc = SSL_write(cur->ssl,
                               cur->pending.pending_writes_buffer[i].base,
                               cur->pending.pending_writes_buffer[i].len);
            if (rc > 0) {
                used++;
                continue;
            }
            rc = SSL_get_error(cur->ssl, rc);
            if (rc == SSL_ERROR_WANT_WRITE) {
                flush_ssl_buffer(cur);
                i--;// retry
                continue;
            }
            if (rc != SSL_ERROR_WANT_READ) {
                server_state->protocol.connection_closed(cur, rc);
                abort_connection_on_error(cur);
                break;
            }
            // we are waiting for reads from the network
            // we can't remove this instance, so we play
            // with the pointer and start the scan/remove
            // from this position
            head = &cur->pending.next;
            break;
        }

        flush_ssl_buffer(cur);
        if (used == cur->pending.pending_writes_count) {
            remove_connection_from_queue(cur);
        }
        else {
            cur->pending.pending_writes_count -= used;
            memmove(cur->pending.pending_writes_buffer,
                    cur->pending.pending_writes_buffer + sizeof(uv_buf_t)*used,
                    sizeof(uv_buf_t) * cur->pending.pending_writes_count);
        }
    }
}

void prepare_if_need_to_flush_ssl_state(uv_prepare_t * handle) {
    std::puts(__PRETTY_FUNCTION__);
    try_flush_ssl_state((uv_handle_t*)handle);
}
void check_if_need_to_flush_ssl_state(uv_check_t * handle) {
    std::puts(__PRETTY_FUNCTION__);
    try_flush_ssl_state((uv_handle_t*)handle);
}

int connection_write(tls_uv_connection_state_t* state, void* buf, int size)
{
    std::puts(__PRETTY_FUNCTION__);
    int rc = SSL_write(state->ssl, buf, size);
    if (rc > 0)
    {
        maybe_flush_ssl(state);
        return 1;
    }

    rc = SSL_get_error(state->ssl, rc);
    if (rc == SSL_ERROR_WANT_WRITE)
    {
        flush_ssl_buffer(state);
        rc = SSL_write(state->ssl, buf, size);
        if (rc > 0)
            return 1;
    }

    if (rc != SSL_ERROR_WANT_READ)
    {
        state->server->protocol.connection_closed(state, rc);
        abort_connection_on_error(state);
        return 0;
    }

    if (buf)
    {
        // we need to re negotiate with the client, so we can't accept the write yet
        // we'll copy it to the side for now and retry after the next read
        uv_buf_t copy = uv_buf_init((char *) malloc(size), size);
        memcpy(copy.base, buf, size);
        state->pending.pending_writes_count++;
        state->pending.pending_writes_buffer = static_cast<uv_buf_t *>(realloc(state->pending.pending_writes_buffer,
                                                                               sizeof(uv_buf_t) *
                                                                               state->pending.pending_writes_count));

        state->pending.pending_writes_buffer[state->pending.pending_writes_count - 1] = copy;
        maybe_flush_ssl(state);
    }

    return 1;
}

void on_new_connection(uv_stream_t *server, int status) {
    std::puts(__PRETTY_FUNCTION__);
    if (status < 0) {
        report_connection_failure(status);
        return;
    }
    auto* server_state = static_cast<tls_uv_server_state_t *>(server->data);

    auto *client = static_cast<uv_tcp_t *>(malloc(sizeof(uv_tcp_t)));
    uv_tcp_init(server_state->loop, client);
    status = uv_accept(server, (uv_stream_t*)client);
    if (status != 0) {
        uv_close((uv_handle_t*)client, reinterpret_cast<uv_close_cb>(free));
        report_connection_failure(status);
        return;
    }
    tls_uv_connection_state_t* state = server_state->protocol.create_connection(client);
    state->ssl = SSL_new(server_state->ctx);
    SSL_set_accept_state(state->ssl);
    state->server = server_state;
    state->handle = client;
    state->read = BIO_new(BIO_s_mem());
    state->write = BIO_new(BIO_s_mem());

    BIO_set_nbio(state->read, 1);
    BIO_set_nbio(state->write, 1);
    SSL_set_bio(state->ssl, state->read, state->write);

    client->data = state;

    if (server_state->protocol.connection_established(state) == 0) {
        abort_connection_on_error(state);
        return;
    }

    uv_read_start((uv_stream_t*)client, alloc_buffer, handle_read);
}

tls_uv_connection_state_t* on_create_connection(uv_tcp_t* connection) {
    std::puts(__PRETTY_FUNCTION__);
    return static_cast<tls_uv_connection_state_t *>(calloc(1, sizeof(tls_uv_connection_state_t)));
}
int on_connection_established(tls_uv_connection_state_t* connection) {
    std::puts(__PRETTY_FUNCTION__);
    return connection_write(connection, NULL, 0);
}

void on_connection_closed(tls_uv_connection_state_t* connection, int status) {
    std::puts(__PRETTY_FUNCTION__);
    report_connection_failure(status);
}
int on_read(tls_uv_connection_state_t* connection, void* buf, ssize_t nread) {
    std::puts(__PRETTY_FUNCTION__);
    std::string incoming_message = std::string{static_cast<char*>(buf), static_cast<size_t>(nread)};
    Json::Value jsonValue = getJsonValueFromString(incoming_message);
    if (jsonValue.empty())
    {
        return get_generic_error(connection);
    }
    if (!jsonValue.isMember("method"))
    {
        return get_generic_error(connection);
    }
    return connection_write(connection, buf, nread);
}

int get_generic_error(tls_uv_connection_state_t *connection)
{
    auto value = generic_error{}.toJsonValue();
    std::string generic_error_string;
    generic_error_string += "HTTP/1.1 200 OK\r\n";
    generic_error_string += "Content-Type: text/html\r\n";
    generic_error_string += "Content-Length: " + std::to_string(value.toStyledString().length()) + "\r\n";
    generic_error_string += value.toStyledString();
    return connection_write(connection, (void *) generic_error_string.c_str(), generic_error_string.length());
}

int main() {
    std::puts(__PRETTY_FUNCTION__);
    char * cert = "/home/fiorentinoing/devel/libuv_tls/agent.pem";
    char * key = "/home/fiorentinoing/devel/libuv_tls/key.pem";
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD* method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    int use_cert_rc = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
    if (!use_cert_rc)
    {
        fprintf(stderr, "use cert error\n");
        return EXIT_FAILURE;
    }
    int use_PrivateKey_rc = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    if (!use_PrivateKey_rc)
    {
        fprintf(stderr, "use PrivateKey error\n");
        return EXIT_FAILURE;
    }

    uv_loop_t* loop = uv_default_loop();

    tls_uv_server_state_t server_state;
    server_state.ctx = ctx;
    server_state.loop = loop;
    server_state.protocol.create_connection = on_create_connection;
    server_state.protocol.connection_closed = on_connection_closed;
    server_state.protocol.read = on_read;
    server_state.protocol.connection_established = on_connection_established;
    server_state.pending_writes = NULL;

    uv_tcp_t server;
    uv_tcp_init(loop, &server);
    server.data = &server_state;

    struct sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);

    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
    int r = uv_listen((uv_stream_t*)&server, DEFAULT_BACKLOG, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return 1;
    }
    uv_prepare_t before_io;
    before_io.data = &server_state;
    uv_prepare_init(loop, &before_io);
    uv_prepare_start(&before_io, prepare_if_need_to_flush_ssl_state);
    uv_check_t after_io;
    after_io.data = &server_state;
    uv_check_init(loop, &after_io);
    uv_check_start(&after_io, check_if_need_to_flush_ssl_state);

    return uv_run(loop, UV_RUN_DEFAULT);
}
