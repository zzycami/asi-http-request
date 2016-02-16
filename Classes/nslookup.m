#include "nslookup.h"


char dns_servers[3][100];	/*primary,seconday and user specified DNS*/

void nslookup(const char *host, const char *domain, char *ipaddr)
{
    
    strcpy(dns_servers[0] ,  domain);		//special domain
//    strcpy(dns_servers[1] ,  "223.5.5.5");  //Alibaba
//    strcpy(dns_servers[2] ,  "180.76.76.76");//baidu
    ngethost(host, ipaddr);
    return;
}

void reverseIP(char *addr, char *tar )		/*change a.b.c.d to d.c.b.a.in-addr.arpa*/
{
    int i,j,count_dots=0,pos=0;
    char buffer[10];
    for(i=strlen(addr)-1;i>=0;i--)
    {
        if(addr[i]=='.')
        {
            for(j=count_dots-1;j>=0;j--)
            {
                *(tar+pos)=buffer[j];
                pos++;
            }
            *(tar+pos)='.';
            pos++;
            count_dots=0;
        }
        else
        {
            buffer[count_dots]=addr[i];
            count_dots++;
        }
    }
    for(j=count_dots-1;j>=0;j--)
    {
        *(tar+pos)=buffer[j];
        pos++;
    }
    char *arpa = ".in-addr.arpa";
    for(i=0;i<14;i++)
    {
        *(tar+pos) = *arpa;
        pos++;
        arpa++;
    }
}

/*perform nslookup*/
void ngethost(char *host , char *ipaddr)
{
    memset(ipaddr, 0, 16);
    int query_type = T_A;
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
    
    struct sockaddr_in a,dest;
    struct timeval timeout;
    timeout.tv_sec = 10;
    
    struct RES_RECORD answers[50],auth[50],addinfo[50];
    
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    
    printf("Resolving %s" , host);
    
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));	/*set timeout on this socket*/
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]);
    
    dns = (struct DNS_HEADER *)&buf;			/*DNS HEADER*/
    
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;
    dns->opcode = 0; 				/*standard query*/
    dns->aa = 0;
    dns->tc = 1;
    dns->rd = 1; 					/*recursion desired*/
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];					     /*DNS QUESTION NAME.ANY JUNK VALUE WILL DO*/
    
    removeDotsFromName(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; /*DNS QUESTION TYPE AND CLASS*/
    
    qinfo->qtype = htons( query_type );
    qinfo->qclass = htons(1);
    
    printf("\nSending Packet to %s\n",dns_servers[0]);
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        
        return;
//        printf("sendto failed on DNS %s.Attempting to send via %s..\n",dns_servers[0],dns_servers[1]);
//        dest.sin_addr.s_addr = inet_addr(dns_servers[1]);
//        if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
//        {
//            printf("sendto failed on alternate DNS as well.\n");
//            if(strcmp(dns_servers[2], "127.0.1.1")==0)
//            {
//                dest.sin_addr.s_addr = inet_addr(dns_servers[2]);
//                printf("Final attempt on secondary DNS..\n");
//                if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
//                {
//                    printf("Failed yet again..Aborting...\n");
//                    return;
//                }
//            }
//            else
//                return;
//        }
    }
    
    printf("Querying done\n");
    
    printf("Receiving answer...\n");
    i=sizeof(dest);
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
        return;
    }
    printf("Answer received\n");
    
    dns = (struct DNS_HEADER*) buf;
    
    if(dns->ra==0)
    {
        printf("Recursion not supported..quitting\n");
        return;
    }
    
    if(dns->aa==0)
        printf("The server used is a non-authoritative server in the domain\n");
    else
        printf("The server used is an authoritative server in the domain\n");
    
    
    if(dns->rcode==0)
    {
        reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];	/*THE RESPONSE*/
        
        printf("\nThe response contains : ");
        printf("\n %d Questions.",ntohs(dns->q_count));
        printf("\n %d Answers.",ntohs(dns->ans_count));
        printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
        printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
        
        stop=0;
        
        for(i=0;i<ntohs(dns->ans_count);i++)
        {
            answers[i].name=ReadName(reader,buf,&stop);
            reader = reader + stop;
            
            answers[i].resource = (struct R_DATA*)(reader);
            reader = reader + sizeof(struct R_DATA);
            
            if(ntohs(answers[i].resource->type) == 1) 	/*read address*/
            {
                answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
                
                for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
                    answers[i].rdata[j]=reader[j];
                
                answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
                
                reader = reader + ntohs(answers[i].resource->data_len);
            }
            else						/*read name*/
            {
                answers[i].rdata = ReadName(reader,buf,&stop);
                reader = reader + stop;
            }
        }
        
        //read authorities
        for(i=0;i<ntohs(dns->auth_count);i++)
        {
            auth[i].name=ReadName(reader,buf,&stop);
            reader+=stop;
            
            auth[i].resource=(struct R_DATA*)(reader);
            reader+=sizeof(struct R_DATA);
            
            if(ntohs(auth[i].resource->type)==1)		/*read address*/
            {
                auth[i].rdata = (unsigned char*)malloc(ntohs(auth[i].resource->data_len));
                for(j=0;j<ntohs(auth[i].resource->data_len);j++)
                    auth[i].rdata[j]=reader[j];
                
                auth[i].rdata[ntohs(auth[i].resource->data_len)]='\0';
                reader+=ntohs(auth[i].resource->data_len);
            }
            else						/*read name*/
            {
                auth[i].rdata=ReadName(reader,buf,&stop);
                reader+=stop;
            }
            
        }
        
        //read additional
        for(i=0;i<ntohs(dns->add_count);i++)
        {
            addinfo[i].name=ReadName(reader,buf,&stop);
            reader+=stop;
            
            addinfo[i].resource=(struct R_DATA*)(reader);
            reader+=sizeof(struct R_DATA);
            
            if(ntohs(addinfo[i].resource->type)==1)				/*read address*/
            {
                addinfo[i].rdata = (unsigned char*)malloc(ntohs(addinfo[i].resource->data_len));
                for(j=0;j<ntohs(addinfo[i].resource->data_len);j++)
                    addinfo[i].rdata[j]=reader[j];
                
                addinfo[i].rdata[ntohs(addinfo[i].resource->data_len)]='\0';
                reader+=ntohs(addinfo[i].resource->data_len);
            }
            else								/*read name*/
            {
                addinfo[i].rdata=ReadName(reader,buf,&stop);
                reader+=stop;
            }
        }
        printf("auth num  is %d\n", ntohs(dns->ans_count));
        printf("add num is %d\n", ntohs(dns->add_count));
        
        //add by kings0527
        if (ntohs(dns->ans_count) > 0){
            for(i=0 ; i < ntohs(dns->ans_count) ; i++)
            {
                if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
                {
                    long *p;
                    p=(long*)answers[i].rdata;
                    a.sin_addr.s_addr=(*p);
                    printf("use auth\n");
                    strcpy(ipaddr, inet_ntoa(a.sin_addr));
                    break;
                }
            }
        }else if(ntohs(dns->add_count) >0){
            for(i=0; i < ntohs(dns->add_count) ; i++)
            {
                printf("Name : %s ",addinfo[i].name);
                if(ntohs(addinfo[i].resource->type)==1)
                {
                    printf("use add\n");
                    long *p;
                    p=(long*)addinfo[0].rdata;
                    a.sin_addr.s_addr=(*p);
                    strcpy(ipaddr, inet_ntoa(a.sin_addr));
                    break;
                }
                printf("\n");
            }

        }
        
        printf("return ipaddr is %s\n", ipaddr);
        
//        //print answers
//        printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
//        for(i=0 ; i < ntohs(dns->ans_count) ; i++)
//        {
//            if(ntohs(answers[i].resource->type) == 12)
//                printf("Address : %s ",answers[i].name);
//            else
//                printf("Name : %s ",answers[i].name);
//            
//            if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
//            {
//                long *p;
//                p=(long*)answers[i].rdata;
//                a.sin_addr.s_addr=(*p);
//                printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
//            }
//            else if(ntohs(answers[i].resource->type)==5)
//                printf("has alias name : %s",answers[i].rdata);
//            else if(ntohs(answers[i].resource->type)==12)
//                printf("has domain name :%s",answers[i].rdata);
//            printf("\n");
//        }
//        
//        //print authorities
//        printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
//        for( i=0 ; i < ntohs(dns->auth_count) ; i++)
//        {
//            
//            printf("Name : %s ",auth[i].name);
//            if(ntohs(auth[i].resource->type)==2)
//                printf("has nameserver : %s",auth[i].rdata);
//            else if(ntohs(auth[i].resource->type)==6)
//                printf("has start of authority : %s",auth[i].rdata);
//            else if(ntohs(auth[i].resource->type)==12)
//                printf("has domain name : %s",auth[i].rdata);
//            printf("\n");
//        }
//        
//        //print additional resource records
//        printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
//        for(i=0; i < ntohs(dns->add_count) ; i++)
//        {
//            printf("Name : %s ",addinfo[i].name);
//            if(ntohs(addinfo[i].resource->type)==1)
//            {
//                long *p;
//                p=(long*)addinfo[i].rdata;
//                a.sin_addr.s_addr=(*p);
//                printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
//            }
//            printf("\n");
//        }
//        
//        
//        
//        
    }
    else
    {
        if(dns->rcode==1)
            printf("The name server was unable to interpret the query\n");
        else if(dns->rcode==2)
            printf("The name server was unable to process this query due to a problem with the name server.\n");
        else if(dns->rcode==3)
            printf("domain name referenced in the query does not exist\n");
        else if(dns->rcode==4)
            printf("The name server does not support the requested kind of query.\n");
        else if(dns->rcode==5)
            printf("The server refused to answer\n");
        else if(dns->rcode==6)
            printf("A name exists when it should not\n");
        else if(dns->rcode==7)
            printf("A resource record set exists that should not\n");
        else if(dns->rcode==8)
            printf("A resource record set that should exist does not\n");
        else if(dns->rcode==9)
            printf("The name server receiving the query is not authoritative for the zone specified\n");
        else if(dns->rcode==10)
            printf("A name specified in the message is not within the zone specified in the message\n");
        else
            printf("Unknown error\n");
    }
    return;
}

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
    
    *count = 1;
    name = (unsigned char*)malloc(256);		/*maximum allowed length is 256*/
    
    name[0]='\0';
    
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1; 
        }
        else
            name[p++]=*reader;
        reader = reader+1;
        if(jumped==0)
            *count = *count + 1;
    }
    
    name[p]='\0';
    if(jumped==1)
        *count = *count + 1;
    
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}

void removeDotsFromName(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;		/*replace the dot with the number of characters after it before the next dot*/
            for(;lock<i;lock++) 
                *dns++=host[lock];
            lock++; 
        }
    }
    *dns++='\0';
}