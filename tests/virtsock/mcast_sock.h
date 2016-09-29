#include <netinet/in.h>

struct mcast_server_sock {
	int sd;
	struct sockaddr_in *sock_conf;
};

struct mcast_client_sock {
	int sd;
	struct sockaddr_in *sock_conf;
	struct ip_mreq *mcast_group;
};

struct mcast_bidir_sock {
	struct mcast_server_sock *tx_sock;
	struct mcast_client_sock *rx_sock;
};

struct mcast_bidir_sock *mcast_bidir_sock_setup(char* tx_mcast_group,
                                                 int tx_mcast_port,
                                                 char* rx_mcast_group,
                                                 int rx_mcast_port);

struct mcast_server_sock *mcast_server_sock_setup(char* tx_mcast_group,
                                                  int tx_mcast_port,
                                                  int loopback);
struct mcast_client_sock *mcast_client_sock_setup(char* mcast_group,
                                                  int mcast_port);
int mcast_client_sock_rx(struct mcast_client_sock *client_sock, void* buf,
                         int buf_len);
int mcast_server_sock_tx(struct mcast_server_sock *serv_sock, void* data,
                         int data_len);
int mcast_bidir_sock_tx(struct mcast_bidir_sock *bidir_sock, void* data,
                        int data_len);
int mcast_bidir_sock_rx(struct mcast_bidir_sock *bidir_sock, void* buf,
                        int buf_len);
int mcast_client_sock_close(struct mcast_client_sock* client_sock);
int mcast_server_sock_close(struct mcast_server_sock* server_sock);
int mcast_bidir_sock_close(struct mcast_bidir_sock* bidir_sock);

