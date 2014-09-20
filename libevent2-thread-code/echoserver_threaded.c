/**
 * Multithreaded, libevent 2.x-based socket server.
 * Copyright (c) 2012 Qi Huang
 * This software is licensed under the BSD license.
 * See the accompanying LICENSE.txt for details.
 *
 * To compile: ./make
 * To run: ./echoserver_threaded
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <time.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <thread>
#include <vector>
#include <mutex>
#include <map>
#include <fstream>
#include <iostream>

//#include "workqueue.h"
bool volatile isRun = true;
/* Port to listen on. */
#define SERVER_PORT 5555
/* Connection backlog (# of backlogged connections to accept). */
#define CONNECTION_BACKLOG 8
/* Number of worker threads.  Should match number of CPU cores reported in 
 * /proc/cpuinfo. */
#define NUM_THREADS 8

/* Behaves similarly to fprintf(stderr, ...), but adds file, line, and function
   information. */
#define errorOut(...) {\
	fprintf(stderr, "%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__);\
	fprintf(stderr, __VA_ARGS__);\
}

#define MAX_PATH_SIZE 1024
#define ROOT_PATH "/home/mike/"
/**
 * Struct to carry around connection (client)-specific data.
 */
typedef struct client {
	/* The client's socket. */
	int fd;

	/* The event_base for this client. */
	struct event_base *evbase;

	/* The bufferedevent for this client. */
	struct bufferevent *buf_ev;

	/* The output buffer for this client. */
	struct evbuffer *output_buffer;
	
	int openFd;
	/* Here you can add your own application-specific attributes which
	 * are connection-specific. */
} client_t;

typedef enum {
	GET,
	HEAD,
	UNKNOWN_C
} command_t;

typedef enum {
	OK,
	NOT_FOUND,
	BAD_REQUEST
} status_t;

typedef enum {
	HTML,
	JPEG,
	JPG,
	PNG,
	CSS,
	JS,
	GIF,
	SWF,
	UNKNOWN_T
} contentType_t;

typedef struct httpHeader {
	command_t command;
	status_t status;
	long length;
	contentType_t type;
} httpHeader_t;

static struct event_base *evbase_accept;
//static workqueue_t workqueue;

/* Signal handler function (defined below). */
static void sighandler(int signal);

static void closeClient(client_t *client) {
	printf("close\n");
	if (client != NULL) {
		if (client->openFd >= 0) {
			close(client->openFd);
			client->openFd = -1;
		}
		if (client->fd >= 0) {
			close(client->fd);
			client->fd = -1;
		}
	}
}

static void closeAndFreeClient(client_t *client) {
	printf("close and free\n");
	if (client != NULL) {
		closeClient(client);
		if (client->buf_ev != NULL) {
			bufferevent_free(client->buf_ev);
			client->buf_ev = NULL;
		}
		if (client->evbase != NULL) {
			event_base_free(client->evbase);
			client->evbase = NULL;
		}
		if (client->output_buffer != NULL) {
			evbuffer_free(client->output_buffer);
			client->output_buffer = NULL;
		}
		free(client);
	}
}

contentType_t getContentType(char* path) {
	contentType_t type;
	char buf[256] = {'\0'};
	char *pch = strrchr(path, '.');
	if (pch != NULL) {
		memcpy(buf, pch + 1, strlen(path) - (pch - path) - 1);
		if (!strcmp(buf, "html"))
			type = HTML;
		else if (!strcmp(buf, "png"))
			type = PNG;
		else if (!strcmp(buf, "jpg"))
			type = JPG;
		else if (!strcmp(buf, "jpeg"))
			type = JPEG;
		else if (!strcmp(buf, "css"))
			type = CSS;
		else if (!strcmp(buf, "js"))
			type = JS;
		else if (!strcmp(buf, "gif"))
			type = GIF;
		else if (!strcmp(buf, "swf"))
			type = SWF;
		else 
			type = UNKNOWN_T;
	}
	else {
		type = UNKNOWN_T;
	}
	return type;
}

void urlDecode(char *str) {
	char tmp[MAX_PATH_SIZE] = {0};
	char *pch = strrchr(str, '?');
	unsigned int i;
	if (pch != NULL)
		str[pch - str] = '\0';
	pch = tmp;
	for(i = 0; i < strlen(str); i++) {
		if (str[i] != '%') {
			*pch++ = str[i];
			continue;
		}
		if (!isdigit(str[i+1]) || !isdigit(str[i+2])){
			*pch++ = str[i];
			continue;
		}
		*pch++ = ((str[i+1] - '0') << 4) | (str[i+2] - '0');
		i+=2;
	}
	*pch = '\0';
	strcpy(str, tmp);
}


int getDepth(char *path) {
	int depth = 0;
	char *ch = strtok(path, "/");
	while(ch != NULL) {
		if(!strcmp(ch, ".."))
			--depth;
		else
			++depth;
		if(depth < 0)
			return -1;
		ch = strtok(NULL, "/");
	}
	return depth;
}

void addHeader(httpHeader_t *h, struct evbuffer *buf) {
	if(h->status == OK) {
		//print response
		evbuffer_add_printf(buf, "HTTP/1.1 200 OK\n");
		char timeStr[64] = {'\0'};
		time_t now = time(NULL);
		strftime(timeStr, 64, "%Y-%m-%d %H:%M:%S", localtime(&now));
		//print date
		evbuffer_add_printf(buf, "Date: %s\n", timeStr);
		//print server
		evbuffer_add_printf(buf, "Server: BESTEUSERVER\n");
		//print content type
		evbuffer_add_printf(buf, "Content-Type: ");
		switch(h->type) {
			case HTML:
				evbuffer_add_printf(buf, "text/html");
				break;
			case JPEG:
			case JPG:
				evbuffer_add_printf(buf, "image/jpeg");
				break;
			case PNG:
				evbuffer_add_printf(buf, "image/png");
				break;
			case CSS:
				evbuffer_add_printf(buf, "text/css");
				break;
			case JS:
				evbuffer_add_printf(buf, "application/x-javascript");
				break;
			case GIF:
				evbuffer_add_printf(buf, "image/gif");
				break;
			case SWF:
				evbuffer_add_printf(buf, "application/x-shockwave-flash");
				break;
			default:
				evbuffer_add_printf(buf, "text/html");
		}
		evbuffer_add_printf(buf, "\n");
		//print content length
		evbuffer_add_printf(buf, "Content-Length: %lu\n", h->length);
		//print connection close
		evbuffer_add_printf(buf, "Connection: close\n\n");
	}
}
/**
 * Called by libevent when the write buffer reaches 0.  We only
 * provide this because libevent expects it, but we don't use it.
 */
void buffered_on_write(struct bufferevent *bev, void *arg) {
	printf("On write\n");
	//closeClient((client_t *) arg);
}
/**
 * Called by libevent when there is data to read.
 */
void buffered_on_read(struct bufferevent *bev, void *arg) {
	client_t *client = (client_t *)arg;
	char *line;
	size_t n;
	/* If we have input data, the number of bytes we have is contained in
	 * bev->input->off. Copy the data from the input buffer to the output
	 * buffer in 4096-byte chunks. There is a one-liner to do the whole thing
	 * in one shot, but the purpose of this server is to show actual real-world
	 * reading and writing of the input and output buffers, so we won't take
	 * that shortcut here. */
	struct evbuffer *input =  bufferevent_get_input(bev);
	line = evbuffer_readln(input, &n, EVBUFFER_EOL_CRLF);
	char cmd[256], protocol[256], path[MAX_PATH_SIZE];
	httpHeader_t httpHeader;
	httpHeader.command = UNKNOWN_C;
	httpHeader.status = OK;
	if (n != 0) {
		int scaned = sscanf(line, "%s %s %s\n", cmd, path, protocol);
		if (scaned == 3) {
			if (!strcmp(cmd, "GET")) {
				httpHeader.command = GET;
			}
			else if (!strcmp(cmd, "HEAD")) {
				httpHeader.command = HEAD;
			}
			else { 
				httpHeader.command = UNKNOWN_C;
			}
		/*	if (strcmp(protocol, "HTTP/1.1")) {
				printf("BAD PROTOCOL%s\n", protocol);
				httpHeader.status = BAD_REQUEST;
			}*/
			if (path[0] != '/') {
				printf("BAD INPUtT\n");
				httpHeader.status = BAD_REQUEST;
			}
			urlDecode(path);
			httpHeader.type = getContentType(path);
			if (getDepth(path) == -1) {
				printf("BAD DEPTH\n");
				httpHeader.status = BAD_REQUEST;
			}
		}
		else {
			printf("Bad scanned\n");
			httpHeader.status = BAD_REQUEST;
		}
	}
	else {
		printf("OOO BAD N\n");
		httpHeader.status = BAD_REQUEST;
	}
	switch (httpHeader.status) {
		case BAD_REQUEST:
			printf("Bad request\n");
			break;
		case OK:
			printf("OK\n");
			break;
		case NOT_FOUND:
			printf("NOt found\n");
			break;
	}
	switch (httpHeader.command) {
		case UNKNOWN_C:
			printf("UNKNOWS\n");
			break;
		case GET:
			printf("GET\n");
			break;
		case HEAD:
			printf("HEAD\n");
			break;
	}
	printf("%s\n", path);
	free(line);
	if (httpHeader.status != BAD_REQUEST) {
		char fullPath[2048] = {'\0'};
		strcpy(fullPath, ROOT_PATH);
		strcat(fullPath, path);
		int fd = open(fullPath, O_RDONLY);
		if (fd < 0) {
			httpHeader.status = NOT_FOUND;
			printf("Can't open %s", fullPath);
		}
		client->openFd = -1;
		struct stat st;
		httpHeader.length = lseek(fd, 0, SEEK_END);
		if (httpHeader.length == -1 || lseek(fd, 0, SEEK_SET) == -1) {
			httpHeader.status = BAD_REQUEST;
			printf("Cant seek\n");
		}
		addHeader(&httpHeader, client->output_buffer);
		if (fstat(fd, &st) < 0) {
			perror("fstat");
		}
		if (fd != -1 && httpHeader.status == OK && httpHeader.command == GET) {
			evbuffer_set_flags(client->output_buffer, EVBUFFER_FLAG_DRAINS_TO_FD);
			if(evbuffer_add_file(client->output_buffer, fd, 0, httpHeader.length) != 0) {
				perror("add file");
			}
		}
	//	printf("%d\n", fd);
	}

	//evbuffer_add(client->output_buffer, "AAA", 3);
	/*
	while ((line = evbuffer_readln(input, &n, EVBUFFER_EOL_CRLF))) {
		evbuffer_add(client->output_buffer, line, n);
		evbuffer_add(client->output_buffer, "\n", 1);
		free(line);
	}*/
	//evbuffer_add_printf(client->output_buffer, "HTTP/1.1 200 OK\r\rContent-Type: text/html\r\nDate: Sun, 14 Sep 2014 08:39:53 GMT\r\nContent-Length: 5\r\n\r\n OKK\r\n");
	//  while (evbuffer_get_length(input) > 0) {
	/* Remove a chunk of data from the input buffer, copying it into our
	 * local array (data). */
	//    nbytes = evbuffer_remove(input, data, 4096); 
	/* Add the chunk of data from our local array (data) to the client's
	 * output buffer. */
	//  evbuffer_add(client->output_buffer, data, nbytes);

	//}

	/* Send the results to the client.  This actually only queues the results
	 * for sending. Sending will occur asynchronously, handled by libevent. */
	if (bufferevent_write_buffer(bev, client->output_buffer) == -1) {
		errorOut("Error sending data to client on fd %d\n", client->fd);
	}

	//bufferevent_setcb(bev, NULL, buffered_on_write, NULL, NULL);
	//bufferevent_enable(bev, EV_WRITE);
}


/**
 * Called by libevent when there is an error on the underlying socket
 * descriptor.
 */
void buffered_on_error(struct bufferevent *bev, short what, void *arg) {
	printf("an error: %s\n", strerror(errno));
	closeClient((client_t *)arg);
}

static void server_job_function(struct job *job) {
	client_t *client = (client_t *)job->user_data;

	event_base_dispatch(client->evbase);
	closeAndFreeClient(client);
	free(job);
}

/**
 * This function will be called by libevent when there is a connection
 * ready to be accepted.
 */
void on_accept(evutil_socket_t fd, short ev, void *arg) {
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	//workqueue_t *workqueue = (workqueue_t *)arg;
	client_t *client;
	job_t *job;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd < 0) {
		warn("accept failed");
		return;
	}

	/* Set the client socket to non-blocking mode. */
	if (evutil_make_socket_nonblocking(client_fd) < 0) {
		warn("failed to set client socket to non-blocking");
		close(client_fd);
		return;
	}

	/* Create a client object. */
	if ((client = (client_t*)malloc(sizeof(*client))) == NULL) {
		warn("failed to allocate memory for client state");
		close(client_fd);
		return;
	}
	memset(client, 0, sizeof(*client));
	client->fd = client_fd;
	client->openFd = -1;
	/* Add any custom code anywhere from here to the end of this function
	 * to initialize your application-specific attributes in the client struct.
	 */

	if ((client->output_buffer = evbuffer_new()) == NULL) {
		warn("client output buffer allocation failed");
		closeAndFreeClient(client);
		return;
	}

	if ((client->evbase = event_base_new()) == NULL) {
		warn("client event_base creation failed");
		closeAndFreeClient(client);
		return;
	}

	/* Create the buffered event.
	 *
	 * The first argument is the file descriptor that will trigger
	 * the events, in this case the clients socket.
	 *
	 * The second argument is the callback that will be called
	 * when data has been read from the socket and is available to
	 * the application.
	 *
	 * The third argument is a callback to a function that will be
	 * called when the write buffer has reached a low watermark.
	 * That usually means that when the write buffer is 0 length,
	 * this callback will be called.  It must be defined, but you
	 * don't actually have to do anything in this callback.
	 *
	 * The fourth argument is a callback that will be called when
	 * there is a socket error.  This is where you will detect
	 * that the client disconnected or other socket errors.
	 *
	 * The fifth and final argument is to store an argument in
	 * that will be passed to the callbacks.  We store the client
	 * object here.
	 */
	client->buf_ev = bufferevent_socket_new(client->evbase, client_fd,
			BEV_OPT_CLOSE_ON_FREE);
	if ((client->buf_ev) == NULL) {
		warn("client bufferevent creation failed");
		closeAndFreeClient(client);
		return;
	}
	bufferevent_setcb(client->buf_ev, buffered_on_read, buffered_on_write,
			buffered_on_error, client);

	/* We have to enable it before our callbacks will be
	 * called. */
	bufferevent_enable(client->buf_ev, EV_READ);

	/* Create a job object and add it to the work queue. */
	if ((job = (job_t*)malloc(sizeof(*job))) == NULL) {
		warn("failed to allocate memory for job state");
		closeAndFreeClient(client);
		return;
	}
	job->job_function = server_job_function;
	job->user_data = client;

	//workqueue_add_job(workqueue, job);
}

/**
 * Run the server.  This function blocks, only returning when the server has 
 * terminated.
 */
int runServer(void) {
	evutil_socket_t listenfd;
	struct sockaddr_in listen_addr;
	struct event *ev_accept;
	int reuseaddr_on;

	/* Set signal handlers */
	sigset_t sigset;
	sigemptyset(&sigset);
	struct sigaction siginfo;
	siginfo.sa_handler = sighandler;
	siginfo.sa_mask = sigset;
	siginfo.sa_flags = SA_RESTART;

	sigaction(SIGINT, &siginfo, NULL);
	sigaction(SIGTERM, &siginfo, NULL);

	/* Create our listening socket. */
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		err(1, "listen failed");
	}

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	listen_addr.sin_port = htons(SERVER_PORT);
	if (bind(listenfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) 
			< 0) {
		err(1, "bind failed");
	}
	if (listen(listenfd, CONNECTION_BACKLOG) < 0) {
		err(1, "listen failed");
	}
	reuseaddr_on = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
			sizeof(reuseaddr_on));

	/* Set the socket to non-blocking, this is essential in event
	 * based programming with libevent. */
	if (evutil_make_socket_nonblocking(listenfd) < 0) {
		err(1, "failed to set server socket to non-blocking");
	}

	if ((evbase_accept = event_base_new()) == NULL) {
		perror("Unable to create socket accept event base");
		close(listenfd);
		return 1;
	}

	/* Initialize work queue. */
	/*if (workqueue_init(&workqueue, NUM_THREADS)) {
		perror("Failed to create work queue");
		close(listenfd);
		workqueue_shutdown(&workqueue);
		return 1;
	}*/

	/* We now have a listening socket, we create a read event to
	 * be notified when a client connects. */
	std::ios::sync_with_stdio(false);
	try {
		auto threadDeleter = [&] (std::thread *t) { isRun = false; t->join(); delete t; };
		typedef std::unique_ptr<std::thread, decltype(threadDeleter)> threadPtr;
		typedef std::vector<threadPtr> threadPool;
		threadPool threads;
		for (int i = 0 ; i < NUM_THREADS; ++i)
		{
			threadPtr t(new std::thread(requestThread), threadDeleter);
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			threads.push_back(std::move(t));
		}
		std::cin.get();
		isRun = false;
	} catch (std::exception const &e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}

	ev_accept = event_new(evbase_accept, listenfd, EV_READ|EV_PERSIST,
			on_accept, NULL);//(void *)&workqueue);
	event_add(ev_accept, NULL);

	printf("Server running.\n");

	/* Start the event loop. */
	event_base_dispatch(evbase_accept);

	event_base_free(evbase_accept);
	evbase_accept = NULL;

	close(listenfd);

	printf("Server shutdown.\n");

	return 0;
}

/**
 * Kill the server.  This function can be called from another thread to kill
 * the server, causing runServer() to return.
 */
void killServer(void) {
	fprintf(stdout, "Stopping socket listener event loop.\n");
	if (event_base_loopexit(evbase_accept, NULL)) {
		perror("Error shutting down server");
	}
	fprintf(stdout, "Stopping workers.\n");
	//workqueue_shutdown(&workqueue);
}

static void sighandler(int signal) {
	fprintf(stdout, "Received signal %d: %s.  Shutting down.\n", signal,
			strsignal(signal));
	killServer();
}

/* Main function for demonstrating the echo server.
 * You can remove this and simply call runServer() from your application. */
int main(int argc, char *argv[]) {
	return runServer();
}
