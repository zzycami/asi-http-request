#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>


#define T_A 1 			/*Ipv4 address*/
#define T_NS 2 			/*Nameserver*/
#define T_CNAME 5 		/*canonical name*/
#define T_SOA 6 		/*start of authority zone */
#define T_PTR 12 		/*domain name pointer */
#define T_MX 15 		/*Mail server*/

void reverseIP(char *,char *);
void ngethost (char*,char*);
void removeDotsFromName(unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);

//add by kings0527
void nslookup(const char *host, const char *domain, char *ipaddr);

/*The structure of the DNS packet will be:
	16 bits:ID
	16 bits:header
	16 bits:question
	16 bits:answer
	16 bits:authoritative answer
	16 bits:additional info*/

/*DNS header*/
struct DNS_HEADER
{
    unsigned short id; 	// identification number
    
    unsigned char rd :1; 	// recursion desired
    unsigned char tc :1; 	// truncated message
    unsigned char aa :1; 	// authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; 	// query/response flag
    
    unsigned char rcode :4; // response code
    unsigned char cd :1; 	// checking disabled
    unsigned char ad :1; 	// authenticated data
    unsigned char z :1; 	// reserved and unused
    unsigned char ra :1; 	// recursion available
    
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct QUESTION				/*QUESTION DATA*/
{
    unsigned short qtype;		/*query type:IN,NS,CNAME,SOA,PTR,MX*/
    unsigned short qclass;		/*query class:IN or CHAOS*/
};


#pragma pack(push, 1)
struct R_DATA				/*RESOURCE RECORD DATA*/
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)


struct RES_RECORD			/*RESOURCE RECORD FIELD:AUTHORITATIVE,ANSWER or ADDITIONAL*/
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

typedef struct				/*QUESTION FIELD*/
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;