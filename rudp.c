#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "event.h"
#include "rudp.h"
#include "rudp_api.h"

// Probability of packet loss
#define DROP 0

// RUDP states
enum {SYN_SENT, OPENING, OPEN, FIN_SENT};

// Pointer to the head of the sockets list
struct sockets *sockets_list_head = NULL;

struct sockets {
	rudp_socket_t rsock;
	int closeRequested;
	int (*recv_handler)(rudp_socket_t, struct sockaddr_in *, char *, int);
	int (*handler)(rudp_socket_t, rudp_event_t, struct sockaddr_in *);
	struct session *sessions_list_head;
	struct sockets *next;
};

struct data {
	void *item;
	int len;
	struct data *next;
};

struct rudp_packet {
	struct rudp_hdr header;
	int payload_length;
	char payload[RUDP_MAXPKTSIZE];
};

struct sender_session {
	int status;
	u_int32_t seqNo;//Seq Number used for sending
	struct rudp_packet *sliding_window[RUDP_WINDOW]; // Sliding window
	int retransmission_attempts[RUDP_WINDOW]; // Retransmissions for each packet in the window
	struct data *data_queue; // Queue of unsent data
	int sessionFinished; // Has the FIN we sent been ACKed?
	void * syn_timeout_arg; // Argument pointer used to delete SYN timeout event
	void * fin_timeout_arg; // Argument pointer used to delete FIN timeout event
	void * data_timeout_arg[RUDP_WINDOW]; // Argument pointers used to DATA delete timeout events
	int syn_retransmit_attempts;
	int fin_retransmit_attempts;
};

struct receiver_session {
	int status;
	u_int32_t expected_seqNo;//Expected seq number used for receiving
	int sessionFinished; // Have we received a FIN from the sender?
};

struct session {
	struct sender_session *sender;
	struct receiver_session *receiver;
	struct sockaddr_in *address; // Peer address
	struct session* next; // Next pointer in linked list
};


struct timeoutargs{
	rudp_socket_t fd;
	struct rudp_packet *packet;
	struct sockaddr_in *recipient;
};

// Prototypes
int receiveCallback(int file, void *arg);
int timeoutCallback(int currentRetryAttempts, void *args);
int send_packet(int isAck, rudp_socket_t rsocket, struct rudp_packet *p, struct sockaddr_in *recipient,int retransmission);

// Whether or not the random number generator has been seeded
int rng_seeded = 0;

/*
 * rudp_socket: Create a RUDP socket.
 * May use a random port by setting port to zero.
 */
rudp_socket_t rudp_socket(int port) {
	// Seed random number generator
	if(rng_seeded ==0) {
		srand(time(NULL));
		rng_seeded = 1;
	}
	int sockfd;
	struct sockaddr_in address;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0) {
		perror("socket");
		return (rudp_socket_t)NULL;
	}

	bzero(&address, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(port);

	if( bind(sockfd, (struct sockaddr *) &address, sizeof(address)) < 0) {
		perror("bind");
		return NULL;
	}

	rudp_socket_t socket = (rudp_socket_t)sockfd;

	// Create new sockets struct and add to list of sockets
	struct sockets *newSocket = malloc(sizeof(struct sockets));
	newSocket->rsock = socket;
	newSocket->closeRequested=0;
	newSocket->sessions_list_head = NULL;
	newSocket->next = NULL;
	newSocket->handler=NULL;
	newSocket->recv_handler=NULL;

	if(sockets_list_head == NULL) {
		sockets_list_head = newSocket;
	}
	else {
		struct sockets *temp = sockets_list_head;
		while(temp->next != NULL) {
			temp = temp->next;
		}
		temp->next = newSocket;
	}

	// Register callback event for this socket descriptor
	if(event_fd(sockfd,receiveCallback, sockfd, "receiveCallback") < 0) {
		fprintf(stderr, "Error registering receive callback function");
	}

	return socket;
}

/* Callback function executed when something is received on fd */
int receiveCallback(int file, void *arg)
{
	char buf[sizeof(struct rudp_packet)];
	struct sockaddr_in sender;
	size_t sender_length = sizeof(struct sockaddr_in);
	recvfrom(file, &buf, sizeof(struct rudp_packet), 0, (struct sockaddr *)&sender, &sender_length);

	struct rudp_packet *received_packet = malloc(sizeof(struct rudp_packet));
	bcopy(&buf, received_packet, sizeof(struct rudp_packet));

	struct rudp_hdr rudpheader = received_packet->header;
	char *type=malloc(5);
	int t=rudpheader.type;
	if(t==1)
		type="DATA";
	else if(t==2)
		type="ACK";
	else if(t==4)
		type="SYN";
	else if(t==5)
		type="FIN";
	else
		type="BAD";

	printf("Received %s packet from %s:%d seq number=%u on socket=%d\n",type, inet_ntoa(sender.sin_addr), ntohs(sender.sin_port),rudpheader.seqno,file);

	// Locate the correct socket in the socket list
	if(sockets_list_head == NULL) {
		fprintf(stderr, "Error: Attempt to receive on invalid socket. No sockets in the list\n");
		return -1;
	}
	else {
		//We have sockets to check
		struct sockets *temp = sockets_list_head;
		while(temp != NULL) {
			if(temp->rsock == file) {
				break;
			}
			temp = temp->next;
		}
		if(temp->rsock == file) {
			// We found the correct socket, now see if a session already exists for this peer
			if(temp->sessions_list_head == NULL) {
				// The list is empty, so we check if the sender has initiated the protocol properly (by sending a SYN)
				if(rudpheader.type == RUDP_SYN) {
					// SYN Received. Create a new session at the head of the list
					struct session *new_session = malloc(sizeof(struct session));
					new_session->address = malloc(sizeof(struct sockaddr_in));
					bcopy(&sender, new_session->address, sizeof(struct sockaddr_in));
					new_session->next=NULL;
					new_session->sender = NULL;
					new_session->receiver = malloc(sizeof(struct receiver_session));
					struct receiver_session *new_receiver_session = malloc(sizeof(struct receiver_session));
					new_receiver_session->status = OPENING;
					new_receiver_session->sessionFinished=0;
					new_receiver_session->expected_seqNo = (rudpheader.seqno+(u_int32_t)1);
					new_session->receiver=new_receiver_session;
					temp->sessions_list_head = new_session;

					// ACK
					struct rudp_hdr *ack=malloc(sizeof(struct rudp_hdr));
					ack->type=RUDP_ACK;
					ack->version=RUDP_VERSION;
					ack->seqno=new_session->receiver->expected_seqNo;
					struct rudp_packet *p2 = malloc(sizeof(struct rudp_packet));
					p2->header = *ack;
					p2->payload_length = 0;
					send_packet(1, file, p2, &sender,0);
				}
				else {
					//No sessions exist and we got a non syn packet
					//We ignore this
				}
			}
			else {
				//Some sessions are there to be checked
				int sessionFound = 0;
				// Check if we already have a session for this peer
				struct session *temp2 = temp->sessions_list_head;
				struct session *last_session;
				while(temp2 != NULL) {
					if(temp2->next == NULL) {
						last_session = temp2;
					}
					if(temp2->address->sin_addr.s_addr == sender.sin_addr.s_addr && temp2->address->sin_port == sender.sin_port && temp2->address->sin_family == sender.sin_family) {
						// Found an existing session
						sessionFound = 1;
						break;
					}

					temp2 = temp2->next;
				}
				if(sessionFound == 0) {
					//No session was found for this peer
					if(rudpheader.type == RUDP_SYN) {
						// SYN Received. Create a new session at the head of the list
						struct session *new_session = malloc(sizeof(struct session));
						new_session->address = malloc(sizeof(struct sockaddr_in));
						bcopy(&sender, new_session->address, sizeof(struct sockaddr_in));
						new_session->next=NULL;
						new_session->sender = NULL;
						new_session->receiver = malloc(sizeof(struct receiver_session));
						struct receiver_session *new_receiver_session = malloc(sizeof(struct receiver_session));
						new_receiver_session->status = OPENING;
						new_receiver_session->sessionFinished=0;
						new_receiver_session->expected_seqNo = (rudpheader.seqno+(u_int32_t)1);
						new_session->receiver=new_receiver_session;
						last_session->next = new_session;

						// ACK
						struct rudp_hdr *ack=malloc(sizeof(struct rudp_hdr));
						ack->type=RUDP_ACK;
						ack->version=RUDP_VERSION;
						ack->seqno=new_session->receiver->expected_seqNo;
						struct rudp_packet *p2 = malloc(sizeof(struct rudp_packet));
						p2->header = *ack;
						p2->payload_length = 0;
						send_packet(1, file, p2, &sender,0);
					}
					else {
						//Session does not exist and we received non SYN
						// We ignore it
					}
				}
				else
				{
					//We did find a session for this peer
					if(rudpheader.type == RUDP_SYN) {
						if(temp2->receiver == NULL || temp2->receiver->status==OPENING) {
							// We have a sender session already with this peer, but not a receiver session
							// So we create a receiver session with the peer
							struct receiver_session *new_receiver_session= malloc(sizeof(struct receiver_session));
							new_receiver_session->expected_seqNo = (rudpheader.seqno+(u_int32_t)1);
							new_receiver_session->status = OPENING;
							new_receiver_session->sessionFinished = 0;
							temp2->receiver = malloc(sizeof(struct receiver_session));
							temp2->receiver = new_receiver_session;

							// ACK
							struct rudp_hdr *ack=malloc(sizeof(struct rudp_hdr));
							ack->type=RUDP_ACK;
							ack->version=RUDP_VERSION;
							ack->seqno=temp2->receiver->expected_seqNo;
							struct rudp_packet *p2 = malloc(sizeof(struct rudp_packet));
							p2->header = *ack;
							p2->payload_length = 0;
							send_packet(1, file, p2, &sender,0);

						}
						else {
							//Received a SYN when there is already an active receiver session, so we ignore it
						}
					}
					if(rudpheader.type == RUDP_ACK)
					{
						//We receive an ACK
						u_int32_t ack_sqn=received_packet->header.seqno;
						if(temp2->sender->status==SYN_SENT)
						{
							//This an ACK for a SYN
							u_int32_t syn_sqn=temp2->sender->seqNo;
							if( (ack_sqn-(u_int32_t)1) == syn_sqn)
							{
								//Deleting the retransmission timeout
								event_timeout_delete(timeoutCallback,temp2->sender->syn_timeout_arg);
								temp2->sender->status=OPEN;
								while(temp2->sender->data_queue!=NULL)
								{
									// Break if the window is already full
									if(temp2->sender->sliding_window[RUDP_WINDOW-1]!=NULL)
									{
										break;
									}
									else{
										int index;
										int i;
										//Finding the first unused window slot
										for(i = RUDP_WINDOW-1; i >= 0; i--) {
											if(temp2->sender->sliding_window[i]==NULL) {
												index = i;
											}
										}
										//Send the packet and add it to window and remove from the queue
										struct rudp_hdr *datah=malloc(sizeof(struct rudp_hdr));
										datah->type=RUDP_DATA;
										datah->version=RUDP_VERSION;
										datah->seqno=++syn_sqn;
										temp2->sender->seqNo+=1;
										struct rudp_packet *datap=malloc(sizeof(struct rudp_packet));
										bcopy(datah,&datap->header,sizeof(struct rudp_hdr));
										bcopy(&temp2->sender->data_queue->len,&datap->payload_length,sizeof(int));
										bcopy(temp2->sender->data_queue->item,&datap->payload,datap->payload_length);
										temp2->sender->sliding_window[index]=datap;
										temp2->sender->retransmission_attempts[index]=0;
										temp2->sender->data_queue=temp2->sender->data_queue->next;
										send_packet(0,file,datap,&sender,0);
									}
								}
							}
						}
						else if(temp2->sender->status==OPEN)
						{
							//This is an ACK for DATA
							if(temp2->sender->sliding_window[0]!=NULL)
							{
								//checking if ack for the first item in the window
								if(temp2->sender->sliding_window[0]->header.seqno == (rudpheader.seqno-(u_int32_t)1))
								{
									//We got correct ack
									//Removing the first window item and shifting the rest left
									event_timeout_delete(timeoutCallback,temp2->sender->data_timeout_arg[0]);
									int i;
									if(RUDP_WINDOW==1) {
										temp2->sender->sliding_window[0] = NULL;
										temp2->sender->retransmission_attempts[0] = 0;
										temp2->sender->data_timeout_arg[0] = NULL;
									}
									else {
										for(i = 0; i < RUDP_WINDOW - 1; i++) {
											temp2->sender->sliding_window[i] = temp2->sender->sliding_window[i+1];
											temp2->sender->retransmission_attempts[i] = temp2->sender->retransmission_attempts[i+1];
											temp2->sender->data_timeout_arg[i] = temp2->sender->data_timeout_arg[i+1];

											if(i == RUDP_WINDOW-2) {
												temp2->sender->sliding_window[i+1]=NULL;
												temp2->sender->retransmission_attempts[i+1]=0;
												temp2->sender->data_timeout_arg[i+1] = NULL;
											}
										}
									}

									while(temp2->sender->data_queue!=NULL)
									{
										if(temp2->sender->sliding_window[RUDP_WINDOW-1]!=NULL)
										{
											break;
										}
										else{
											int index;
											int i;
											//Finding the first unused window
											for(i = RUDP_WINDOW-1; i >= 0; i--) {
												if(temp2->sender->sliding_window[i]==NULL) {
													index = i;
												}
											}
											//Send the packet and add it to window and remove from the queue
											struct rudp_hdr *datah=malloc(sizeof(struct rudp_hdr));
											datah->type=RUDP_DATA;
											datah->version=RUDP_VERSION;
											//datah->seqno=ack_sqn;
											temp2->sender->seqNo = (temp2->sender->seqNo + (u_int32_t)1);
											datah->seqno=temp2->sender->seqNo;
											struct rudp_packet *datap=malloc(sizeof(struct rudp_packet));
											bcopy(datah,&datap->header,sizeof(struct rudp_hdr));
											bcopy(&temp2->sender->data_queue->len,&datap->payload_length,sizeof(int));
											bcopy(temp2->sender->data_queue->item,&datap->payload,datap->payload_length);
											temp2->sender->sliding_window[index]=datap;
											temp2->sender->retransmission_attempts[index]=0;
											temp2->sender->data_queue=temp2->sender->data_queue->next;
											send_packet(0,file,datap,&sender,0);
										}
									}
									//Checking for close req
									if(temp->closeRequested==1)
									{
										//Can it be closed now?
										struct session *head_sessions=temp->sessions_list_head;
										while(head_sessions!=NULL)
										{
											if(head_sessions->sender->sessionFinished!=1)
											{
												if(head_sessions->sender->data_queue==NULL &&  head_sessions->sender->sliding_window[0]==NULL && head_sessions->sender->status==OPEN)
												{
													struct rudp_hdr *fin=malloc(sizeof(struct rudp_hdr));
													fin->type=RUDP_FIN;
													fin->version=RUDP_VERSION;
													head_sessions->sender->seqNo+=1;
													fin->seqno=head_sessions->sender->seqNo;
													struct rudp_packet *p = malloc(sizeof(struct rudp_packet));
													bcopy(fin, &p->header,sizeof(struct rudp_hdr));
													p->payload_length = 0;
													send_packet(0, file, p, head_sessions->address,0);
													head_sessions->sender->status=FIN_SENT;
												}
											}
											head_sessions=head_sessions->next;
										}
									}
								}
							}
						}
						else if(temp2->sender->status==FIN_SENT)
						{
							//Handling any ack for fin
							if( (temp2->sender->seqNo+(u_int32_t)1) == received_packet->header.seqno)
							{
								event_timeout_delete(timeoutCallback,temp2->sender->fin_timeout_arg);
								temp2->sender->sessionFinished=1;
								if(temp->closeRequested==1)
								{
									//Can it be closed now?
									struct session *head_sessions=temp->sessions_list_head;
									int allDone=1;
									while(head_sessions!=NULL)
									{
										//printf("head_sessions->sender->sessionFinished = %d, head_session->receiver->sessionFinished = %d\n", head_sessions->sender->sessionFinished, head_sessions->receiver->sessionFinished);
										if(head_sessions->sender->sessionFinished==0)
										{
											allDone=0;
										}
										else if(head_sessions->receiver != NULL && head_sessions->receiver->sessionFinished==0)
										{
											allDone = 0;
										}

										head_sessions=head_sessions->next;
									}
									if(allDone==1)
									{
										if(temp->handler!=NULL)
										{
											temp->handler((rudp_socket_t)file,RUDP_EVENT_CLOSED,&sender);
											event_fd_delete(receiveCallback, file);
											close(file);
										}
									}
								}
							}
							else
							{
								// Received Incorrect ACK for FIN
							}
						}
					}
					else if(rudpheader.type==RUDP_DATA)
					{
						//This is when we handle a data packet

						// If our receiver is OPENING, we can move it to OPEN if the correct DATA is received
						if(temp2->receiver->status == OPENING) {
							if(rudpheader.seqno==temp2->receiver->expected_seqNo)
							{
								temp2->receiver->status = OPEN;
							}
						}

						if(rudpheader.seqno==temp2->receiver->expected_seqNo)
						{
							//The seq numbers match correctly and we ack the data
							struct rudp_hdr *ack=malloc(sizeof(struct rudp_hdr));
							ack->type=RUDP_ACK;
							ack->version=RUDP_VERSION;
							//ack->seqno=(temp2->receiver->expected_seqNo+(u_int32_t)1)%UINT32_MAX;
							ack->seqno=(rudpheader.seqno+(u_int32_t)1);
							struct rudp_packet *p = malloc(sizeof(struct rudp_packet));
							p->header = *ack;
							p->payload_length = 0;
							send_packet(1, file, p, &sender,0);
							temp2->receiver->expected_seqNo=ack->seqno;
							//temp2->receiver->expected_seqNo=(temp2->receiver->expected_seqNo+(u_int32_t)1)%UINT32_MAX;

							//Passing the data to the application
							if(temp->recv_handler!=NULL)
								temp->recv_handler(file, &sender,(void*)&received_packet->payload,received_packet->payload_length);

						}
						// Handle the case where an ACK was lost
						else if(SEQ_GEQ(rudpheader.seqno, (temp2->receiver->expected_seqNo-(u_int32_t)RUDP_WINDOW)) &&
								SEQ_LT(rudpheader.seqno, temp2->receiver->expected_seqNo)) {
							//The seq numbers match correctly and we ack the data
							struct rudp_hdr *ack=malloc(sizeof(struct rudp_hdr));
							ack->type=RUDP_ACK;
							ack->version=RUDP_VERSION;
							ack->seqno=(rudpheader.seqno+(u_int32_t)1);
							//temp2->receiver->expected_seqNo=ack->seqno;
							struct rudp_packet *p = malloc(sizeof(struct rudp_packet));
							p->header = *ack;
							p->payload_length = 0;
							send_packet(1, file, p, &sender,0);
							//temp2->receiver->expected_seqNo=(temp2->receiver->expected_seqNo+(u_int32_t)1)%UINT32_MAX;
						}
					}
					else if(rudpheader.type==RUDP_FIN)
					{
						//This is when we handle a FIN
						if(temp2->receiver->status == OPEN) {
							if(rudpheader.seqno==temp2->receiver->expected_seqNo)
							{
								// If the FIN is correct, we can ACK it
								struct rudp_hdr *ack=malloc(sizeof(struct rudp_hdr));
								ack->type=RUDP_ACK;
								ack->version=RUDP_VERSION;
								ack->seqno=(temp2->receiver->expected_seqNo+(u_int32_t)1);
								struct rudp_packet *p2 = malloc(sizeof(struct rudp_packet));
								p2->header = *ack;
								p2->payload_length = 0;
								temp2->receiver->sessionFinished = 1;
								send_packet(1, file, p2, &sender,0);

								// See if we can close the socket
								if(temp->closeRequested==1)
								{
									//Can it be closed now?
									struct session *head_sessions=temp->sessions_list_head;
									int allDone=1;
									while(head_sessions!=NULL)
									{
										if(head_sessions->sender->sessionFinished==0)
											allDone=0;
										else if(head_sessions->receiver != NULL && head_sessions->receiver->sessionFinished==0)
											allDone = 0;

										head_sessions=head_sessions->next;
									}
									if(allDone==1)
									{
										if(temp->handler!=NULL)
										{
											temp->handler(file,RUDP_EVENT_CLOSED,&sender);
											event_fd_delete(receiveCallback, file);
											close(file);
										}
									}
								}
							}
							else
							{
								//FIN received with bad seq no
							}
						}
					}
				}
			}
		}
	}

	return 0;
}

/* 
 *rudp_close: Close socket 
 */ 

int rudp_close(rudp_socket_t rsocket) {
	struct sockets *temp = sockets_list_head;
	while(temp->next != NULL) {
		if(temp->rsock == rsocket) {
			break;
		}
		temp = temp->next;
	}
	if(temp->rsock == rsocket) {
		temp->closeRequested=1;
		return 0;
	}
	return -1;
}

/* 
 *rudp_recvfrom_handler: Register receive callback function 
 */ 

int rudp_recvfrom_handler(rudp_socket_t rsocket, 
			  int (*handler)(rudp_socket_t, struct sockaddr_in *, 
					 char *, int)) {

	if(handler == NULL) {
		fprintf(stderr, "rudp_recvfrom_handler failed: handler callback is null\n");
		return -1;
	}
	// Find the proper socket from the socket list
		struct sockets *temp = sockets_list_head;
		while(temp->next != NULL) {
			if(temp->rsock == rsocket) {
				break;
			}
			temp = temp->next;
		}
		// Insert an extra check to handle case where invalid rsock is used
		if(temp->rsock == rsocket) {
			temp->recv_handler = handler;
			return 0;
		}
	return -1;
}

/* 
 *rudp_event_handler: Register event handler callback function 
 */ 
int rudp_event_handler(rudp_socket_t rsocket, 
		       int (*handler)(rudp_socket_t, rudp_event_t, 
				      struct sockaddr_in *)) {

	if(handler == NULL) {
		fprintf(stderr, "rudp_event_handler failed: handler callback is null\n");
		return -1;
	}

	// Find the proper socket from the socket list
	struct sockets *temp = sockets_list_head;
	while(temp->next != NULL) {
		if(temp->rsock == rsocket) {
			break;
		}
		temp = temp->next;
	}
	// Insert an extra check to handle case where invalid rsock is used
	if(temp->rsock == rsocket) {
		temp->handler = handler;
		return 0;
	}
	return -1;
}


/* 
 * rudp_sendto: Send a block of data to the receiver. 
 */

int rudp_sendto(rudp_socket_t rsocket, void* data, int len, struct sockaddr_in* to) {

	if(len < 0 || len > RUDP_MAXPKTSIZE) {
		fprintf(stderr, "rudp_sendto Error: Attempting to send with invalid max packet size\n");
		return -1;
	}

	if(rsocket < 0) {
		fprintf(stderr, "rudp_sendto Error: Attempting to send on invalid socket\n");
		return -1;
	}

	if(to == NULL) {
		fprintf(stderr, "rudp_sendto Error: Attempting to send to an invalid address\n");
		return -1;
	}

	int new_session_created=1;
	int seq_no=0;
	if(sockets_list_head == NULL) {
		fprintf(stderr, "Error: Attempt to send on invalid socket. No sockets in the list\n");
		return -1;
	}
	else {
		// Find the correct socket in our list
		struct sockets *temp = sockets_list_head;
		while(temp != NULL) {
			if(temp->rsock == rsocket) {
				break;
			}
			temp = temp->next;
		}
		if(temp->rsock == rsocket) {
			// We found the correct socket, now see if a session already exists for this peer
			struct data *data_item = malloc(sizeof(struct data));
			data_item->item=malloc(len);
			bcopy(data,data_item->item,len);
			data_item->len = len;
			data_item->next = NULL;
			if(temp->sessions_list_head == NULL) {
				// The list is empty, so we create a new session at the head of the list
				// This will be a sender address
				struct session *new_session = malloc(sizeof(struct session));
				new_session->address = to;
				new_session->next = NULL;
				new_session->receiver = NULL;
				new_session->sender = malloc(sizeof(struct sender_session));
				struct sender_session *new_sender_session = malloc(sizeof(struct sender_session));
				new_sender_session->status=SYN_SENT;
				//new_sender_session->seqNo = rand();
				new_sender_session->seqNo = rand(); // HELP
				new_sender_session->sessionFinished=0;
				//Creating a new session and adding the data to the queue
				new_sender_session->data_queue = data_item;
				new_session->sender = new_sender_session;

				int i;
				for(i = 0; i < RUDP_WINDOW; i++) {
					new_sender_session->retransmission_attempts[i] = 0;
					new_sender_session->data_timeout_arg[i] = 0;
					new_sender_session->sliding_window[i] = NULL;
				}
				new_sender_session->syn_retransmit_attempts=0;
				new_sender_session->fin_retransmit_attempts=0;
				seq_no=new_sender_session->seqNo;
				temp->sessions_list_head=new_session;
			}
			else {
				int sessionFound = 0;
				// Check if we already have a session for this peer
				struct session *temp2 = temp->sessions_list_head;
				struct session *last_in_list;
				while(temp2 != NULL) {
					if(temp2->address->sin_addr.s_addr == to->sin_addr.s_addr && temp2->address->sin_port == to->sin_port && temp2->address->sin_family == to->sin_family)
					{
						// If the window has any free slots and the data queue is empty and the state is OPEN, we will send the packet
						int data_is_queued = 0;
						int we_must_queue = 1;

						if(temp2->sender==NULL)
						{
							struct sender_session *new_sender_session=malloc(sizeof(struct sender_session));
							new_sender_session->data_queue=NULL;
							new_sender_session->fin_retransmit_attempts=0;
							new_sender_session->status=SYN_SENT;
							new_sender_session->seqNo = rand();
							new_sender_session->sessionFinished=0;
							//Creating a new session and adding the data to the queue
							new_sender_session->data_queue = data_item;

							int i;
							for(i = 0; i < RUDP_WINDOW; i++) {
								new_sender_session->retransmission_attempts[i] = 0;
								new_sender_session->data_timeout_arg[i] = 0;
								new_sender_session->sliding_window[i] = NULL;
							}
							new_sender_session->syn_retransmit_attempts=0;
							new_sender_session->fin_retransmit_attempts=0;
							seq_no=new_sender_session->seqNo;
							temp2->sender=malloc(sizeof(struct sender_session));
							temp2->sender = new_sender_session;
							struct rudp_hdr *syn=malloc(sizeof(struct rudp_hdr));
							syn->type=RUDP_SYN;
							syn->version=RUDP_VERSION;
							syn->seqno=seq_no;
							struct rudp_packet *p = malloc(sizeof(struct rudp_packet));
							p->header = *syn;
							p->payload_length = 0;
							send_packet(0, rsocket, p, to,0);
							new_session_created = 0;//Dont send the SYN twice
							break;
						}



						if(temp2->sender->data_queue != NULL)
							data_is_queued = 1;

						if(temp2->sender->status == OPEN && data_is_queued==0) {
							int i;
							for(i = 0; i < RUDP_WINDOW; i++) {
								if(temp2->sender->sliding_window[i] == NULL) {
									struct rudp_hdr *datah=malloc(sizeof(struct rudp_hdr));
									datah->type=RUDP_DATA;
									datah->version=RUDP_VERSION;
									temp2->sender->seqNo = (temp2->sender->seqNo + (u_int32_t)1);
									datah->seqno=temp2->sender->seqNo;
									struct rudp_packet *datap=malloc(sizeof(struct rudp_packet));
									bcopy(datah,&datap->header,sizeof(struct rudp_hdr));
									bcopy(&len, &datap->payload_length, sizeof(int));
									bcopy(data, &datap->payload, len);
									temp2->sender->sliding_window[i]=datap;
									temp2->sender->retransmission_attempts[i]=0;
									send_packet(0,rsocket,datap,to,0);
									we_must_queue = 0;
									break;
								}
							}
						}

						if(we_must_queue == 1) {
							// If so, queue the data
							if(temp2->sender->data_queue == NULL) {
								// First entry in the data queue
								temp2->sender->data_queue = data_item;
							}
							else {
								// Add to end of data queue
								struct data *temp3 = temp2->sender->data_queue;
								while(temp3->next != NULL) {
									temp3 = temp3->next;
								}
								temp3->next = data_item;
							}
						}

						sessionFound = 1;
						new_session_created=0;
						break;
					}
					if(temp2->next==NULL)
						last_in_list=temp2;
					temp2 = temp2->next;
				}
				if(sessionFound == 0) {
					// If not, create a new session and send a SYN
					struct session *new_session = malloc(sizeof(struct session));
					new_session->address = to;
					new_session->next = NULL;
					new_session->receiver = NULL;
					new_session->sender = malloc(sizeof(struct sender_session));
					struct sender_session *new_sender_session = malloc(sizeof(struct sender_session));
					new_sender_session->status=SYN_SENT;
					new_sender_session->seqNo = rand();
					new_sender_session->sessionFinished=0;
					//Creating a new session and adding the data to the queue
					new_sender_session->data_queue = data_item;
					new_session->sender = new_sender_session;

					int i;
					for(i = 0; i < RUDP_WINDOW; i++) {
						new_sender_session->retransmission_attempts[i] = 0;
						new_sender_session->data_timeout_arg[i] = 0;
						new_sender_session->sliding_window[i] = NULL;
					}
					new_sender_session->syn_retransmit_attempts=0;
					new_sender_session->fin_retransmit_attempts=0;
					seq_no=new_sender_session->seqNo;

					//Added to rear of the session list
					last_in_list->next=new_session;
				}
			}
		}
		else {
			fprintf(stderr, "Error: Attempt to send on invalid socket. Socket not found\n");
			return -1;
		}
	}
	if(new_session_created==1)
	{
		//Sending the SYN for the new session
		struct rudp_hdr *syn=malloc(sizeof(struct rudp_hdr));
		syn->type=RUDP_SYN;
		syn->version=RUDP_VERSION;
		syn->seqno=seq_no;
		struct rudp_packet *p = malloc(sizeof(struct rudp_packet));
		p->header = *syn;
		p->payload_length = 0;
		send_packet(0, rsocket, p, to,0);
	}
	return 0;
}

int timeoutCallback(int fd, void *args) {
	struct timeoutargs *timeargs=(struct timeoutargs*)args;
	struct sockets *temp = sockets_list_head;
	while(temp != NULL) {
		if(temp->rsock == timeargs->fd) {
			break;
		}
		temp = temp->next;
	}
	if(temp->rsock == timeargs->fd) {
		int sessionFound = 0;
			// Check if we already have a session for this peer
			struct session *temp2 = temp->sessions_list_head;
			while(temp2 != NULL) {
				if(temp2->address->sin_addr.s_addr == timeargs->recipient->sin_addr.s_addr && temp2->address->sin_port == timeargs->recipient->sin_port && temp2->address->sin_family == timeargs->recipient->sin_family) {
					// Found an existing session
					sessionFound = 1;
					break;
				}

				temp2 = temp2->next;
			}
			if(sessionFound == 1) {
				if(timeargs->packet->header.type==RUDP_SYN)
				{
					if(temp2->sender->syn_retransmit_attempts>=RUDP_MAXRETRANS)
					{
						temp->handler(timeargs->fd,RUDP_EVENT_TIMEOUT,timeargs->recipient);
					}
					else
					{
						temp2->sender->syn_retransmit_attempts++;
						send_packet(0,timeargs->fd,timeargs->packet,timeargs->recipient,1);
					}
				}
				else if(timeargs->packet->header.type==RUDP_FIN)
				{
					if(temp2->sender->fin_retransmit_attempts>=RUDP_MAXRETRANS)
					{
						temp->handler(timeargs->fd,RUDP_EVENT_TIMEOUT,timeargs->recipient);
					}
					else
					{
						temp2->sender->fin_retransmit_attempts++;
						send_packet(0,timeargs->fd,timeargs->packet,timeargs->recipient,1);
					}
				}
				else{
					int i;
					int index;
					for(i = 0; i < RUDP_WINDOW; i++) {
						if(temp2->sender->sliding_window[i] != NULL && temp2->sender->sliding_window[i]->header.seqno==timeargs->packet->header.seqno) {
							index = i;
						}
					}

					if(temp2->sender->retransmission_attempts[index]>=RUDP_MAXRETRANS)
					{
						temp->handler(timeargs->fd,RUDP_EVENT_TIMEOUT,timeargs->recipient);
					}
					else
					{
						temp2->sender->retransmission_attempts[index]++;
						send_packet(0,timeargs->fd,timeargs->packet,timeargs->recipient,1);
					}
				}
			}
		}

	return 0;
}

int send_packet(int isAck, rudp_socket_t rsocket, struct rudp_packet *p, struct sockaddr_in *recipient,int retransmission) {
	// Send packet on UDP socket


	char *type=malloc(5);
	int t=p->header.type;
	if(t==1)
		{type="DATA";}
	else if(t==2)
		{type="ACK";}
	else if(t==4)
		{type="SYN";}
	else if(t==5)
		{type="FIN";}
	else
		{type="BAD";}
	printf("Sending %s packet to %s:%d seq number=%u on socket=%d\n",type, inet_ntoa(recipient->sin_addr), ntohs(recipient->sin_port),p->header.seqno,rsocket);

		if (DROP != 0 && rand() % DROP == 1) {
			  printf("Dropped\n");
		}
		else
		{
			if (sendto(rsocket, p, sizeof(struct rudp_packet), 0, (struct sockaddr*)recipient, sizeof(struct sockaddr_in)) < 0) {
				fprintf(stderr, "rudp_sendto: sendto failed\n");
				return -1;
			}
		}

	if(isAck == 0) {
		// Set a timeout event, unless the packet is an ACK
		struct timeoutargs *timeargs=malloc(sizeof(struct timeoutargs));
		timeargs->packet=malloc(sizeof(struct rudp_packet));
		timeargs->recipient=malloc(sizeof(struct sockaddr_in));
		timeargs->fd=rsocket;
		bcopy(p,timeargs->packet,sizeof(struct rudp_packet));
		bcopy(recipient,timeargs->recipient,sizeof(struct sockaddr_in));
		struct timeval currentTime;
		gettimeofday(&currentTime, NULL);
		struct timeval delay;
		delay.tv_sec = RUDP_TIMEOUT/1000;
		delay.tv_usec= 0;
		struct timeval timeoutTime;
		timeradd(&currentTime, &delay, &timeoutTime);
		struct sockets *temp = sockets_list_head;
		while(temp != NULL) {
			if(temp->rsock == timeargs->fd) {
				break;
			}
			temp = temp->next;
		}
		if(temp->rsock == timeargs->fd) {
			int sessionFound = 0;
				// Check if we already have a session for this peer
				struct session *temp2 = temp->sessions_list_head;
				while(temp2 != NULL) {
					if(temp2->address->sin_addr.s_addr == timeargs->recipient->sin_addr.s_addr && temp2->address->sin_port == timeargs->recipient->sin_port && temp2->address->sin_family == timeargs->recipient->sin_family) {
						// Found an existing session
						sessionFound = 1;
						break;
					}

					temp2 = temp2->next;
				}
				if(sessionFound == 1) {

					if(timeargs->packet->header.type==RUDP_SYN)
					{
						temp2->sender->syn_timeout_arg=timeargs;
					}
					else if(timeargs->packet->header.type==RUDP_FIN)
					{
						temp2->sender->fin_timeout_arg=timeargs;
					}
					else if(timeargs->packet->header.type==RUDP_DATA)
					{
						int i;
						int index;
						for(i = 0; i < RUDP_WINDOW; i++) {
							if(temp2->sender->sliding_window[i] != NULL && temp2->sender->sliding_window[i]->header.seqno==timeargs->packet->header.seqno) {
								index = i;
							}
						}
						temp2->sender->data_timeout_arg[index]=timeargs;
					}
				}
			}
			event_timeout(timeoutTime, timeoutCallback, timeargs, "timeoutCallback");
	}
	return 0;
}
