---
title: "C++ - nestjs - mysql 로깅"
categories: 
  - project
tags:
  - coding
  - C++
  - nestjs
  - mysql
toc: true
---

# 진행중인 프로젝트 설명
```
c++는 클라이언트의 패킷을 저장 및 로그서버에 송신하고
nestjs 로그서버에서 db에 저장 한다.
추후 inline모드로 ubuntu가 fw처럼 동작하도록 하고
nestjs에서는 elk 스택과 연동하여, 중앙로그관리 및 중앙 정책에 따른 클라이언트의 정책 관리, 
패킷 분석 등의 기능을 추가할 예정이다.
```

# C++
- 클라이언트(ubuntu)에서 실행되어 지정한 인터페이스의 패킷을 캡처하여 FILE형태로 원본 패킷을 저장하고,
- socket을 통해 로그서버인 nestjs에 udp로 트래픽로그를 송신한다.

## main.cpp
```cpp
#include <iostream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <thread>
#include <vector>
#include <map>
#include <unistd.h>
#include "myutil.h"
#include "ethernet.h"

#define M_PCAP_OPEN_LIVE_ERROR -1
#define M_PCAP_FIND_ALLDEVS_ERROR -2
#define M_PCAP_INPUT_NUMBER_ERROR -3
#define M_PCAP_ALREADY_CAPTURED_ERROR -4
#define M_CREATE_THREAD_ERROR -5
#define M_DELETE_THREAD_ERROR -6

const std::string SERVER_ADDRESS = "192.168.0.3"; // 로그 서버의 IP
const int BUF_SIZE = 1024;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void pcap_thread_func(pcap_t * ahandle);
int print_get_devs(pcap_t *adhandle, std::map<int, std::pair<pcap_t *, std::thread>>& thread_map);
int delete_thread(std::map<int, std::pair<pcap_t *, std::thread>>& thread_map,int no);

int main(int argc, char **argv) {
    pcap_t *adhandle; // 사용자가 정한 디바이스 핸들
    struct pcap_addr *a;
    std::map<int, std::pair<pcap_t *, std::thread>> thread_map;

    int no = print_get_devs(adhandle, thread_map);
    switch(no) {
        case M_PCAP_ALREADY_CAPTURED_ERROR: 
            break;
        case M_PCAP_FIND_ALLDEVS_ERROR:
            break;
        case M_PCAP_INPUT_NUMBER_ERROR:
            break;
        case M_PCAP_OPEN_LIVE_ERROR:
            break;
        default:
            break;
    }


    for (std::pair<const int, std::pair<pcap_t*, std::thread>>& tmp : thread_map) {
        if (tmp.second.second.joinable()) {
            tmp.second.second.join();
        }
        pcap_close(tmp.second.first);
    }
    thread_map.clear();

    return 0;
}

void packet_handler(u_char *param,
    const struct pcap_pkthdr *header, const u_char *pkt_data) {

    std::string data ="";
    data += getTimeStamp();
    dump_ethernet_header(pkt_data, data);
    auto proto = dump_ip_header(pkt_data, data);
    if (proto == M_TCP) {
        dump_tcp_header(pkt_data, data);
    }
    if (proto == M_UDP) {
        dump_udp_header(pkt_data, data);
    }
    
    // 로그에 대한 로그 생성 방지
    if (data.find("dst_ip="+SERVER_ADDRESS) != std::string::npos && data.find("dst_port=514") != std::string::npos) {
        return;
    }
    auto send_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_socket == -1) {
        std::cout << "create socket error" << std::endl;
    }
    // mac, ip, port 주소 추출후 nestjs에 전송
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(514);
    if (inet_pton(AF_INET, SERVER_ADDRESS.c_str(), &(serv_addr.sin_addr)) != 1) {
        std::cout << "ip 변환 실패" << std::endl;
    }
    sendto(send_socket, data.c_str(), strlen(data.c_str()), 0, (struct sockaddr*)& serv_addr, sizeof(serv_addr));
    close(send_socket);

    // 원본 패킷 file로 저장
    std::ofstream writeFile;
    writeFile.open(getFileName());

    if (writeFile.is_open()) {
        data += getFileData(0,header->caplen, pkt_data);
        std::cout << data << std::endl;
        writeFile.write(data.c_str(), data.size());
    }
    writeFile.close();

    printf("caplen : %d\n", header->caplen);
    printf("len : %d\n", header->len);
}

void pcap_thread_func(pcap_t * ahandle) {
    pcap_loop(ahandle, 0, packet_handler, NULL);
}

int print_get_devs(pcap_t *adhandle, std::map<int, std::pair<pcap_t *, std::thread>>& thread_map) {
    int i = 0;
    int no;
    pcap_if_t *d;
    pcap_if_t * alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return M_PCAP_FIND_ALLDEVS_ERROR;
    }

    for (d=alldevs; d; d=d->next) {
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }
    printf("number : ");
    scanf("%d", &no);

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return M_PCAP_INPUT_NUMBER_ERROR;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i)  break;
    }
    if (!(adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return M_PCAP_OPEN_LIVE_ERROR;
    }

    if (thread_map.find(no) == thread_map.end()) {
        thread_map.insert(std::make_pair(no, std::make_pair(adhandle, std::thread(pcap_thread_func, adhandle))));
    } else {
        printf("selected device is already running.");
        return M_PCAP_ALREADY_CAPTURED_ERROR;
    }

    pcap_freealldevs(alldevs);

    return no;
}

int delete_thread(std::map<int, std::pair<pcap_t *, std::thread>>& thread_map, int no) {
    auto tmp = thread_map.find(no);
    if (tmp == thread_map.end()) {
        printf("delete_thread error - not found");
        return M_DELETE_THREAD_ERROR;
    }
    if (tmp->second.second.joinable()) {
        tmp->second.second.join();
    }
    pcap_breakloop(tmp->second.first);
    thread_map.erase(tmp);
    return 0;
}
```

## ethernet.cpp
```cpp
#include "ethernet.h"

void dump_ethernet_header(const u_char *pkt_data, std::string& str) {
    struct ether_header *header = (struct ether_header *)pkt_data;

    const char *name = NULL;
    std::ostringstream oss;
    u_int8_t *dmac = header->ether_dhost;
    u_int8_t *smac = header->ether_shost;
    u_int16_t type = ntohs(header->ether_type);

    switch (type) {
        case ETHERTYPE_IP:
        name = "IP";
        break;
        case ETHERTYPE_ARP:
        name = "ARP";
        break;
        default:
        name = "Unknwon";
        break;
    }

    oss << std::setfill('0') << std::hex 
        << " src_mac="
        << std::setw(2) << (int)smac[0] << ":" << std::setw(2) << (int)smac[1] << ":"
        << std::setw(2) << (int)smac[2] << ":" << std::setw(2) << (int)smac[3] << ":"
        << std::setw(2) << (int)smac[4] << ":" << std::setw(2) << (int)smac[5]
        << " dst_mac="  
        << std::setw(2) << (int)dmac[0] << ":" << std::setw(2) << (int)dmac[1] << ":"
        << std::setw(2) << (int)dmac[2] << ":" << std::setw(2) << (int)dmac[3] << ":"
        << std::setw(2) << (int)dmac[4] << ":" << std::setw(2) << (int)dmac[5];
   
    printf("%02x:%02x:%02x:%02x:%02x:%02x => " \
        "%02x:%02x:%02x:%02x:%02x:%02x (%s) \n",
    smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
    dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5], name);
    str += oss.str();
}

int dump_ip_header(const u_char *pkt_data, std::string& str) {
    // IP 헤더 추출
    struct ip* ip_header = (struct ip*)(pkt_data + 14);
    std::ostringstream ss;

     // IP 헤더 필드 추출
    uint8_t version = (ip_header->ip_v) & 0x0F;
    uint8_t header_length = (ip_header->ip_hl) * 4; // 바이트 단위로
    uint16_t total_length = ntohs(ip_header->ip_len);
    uint16_t identification = ntohs(ip_header->ip_id);
    uint16_t flags = ntohs(ip_header->ip_off);
    uint16_t fragment_offset = flags & 0x1FFF;
    uint8_t ttl = ip_header->ip_ttl;
    uint8_t protocol = ip_header->ip_p;
    uint16_t checksum = ntohs(ip_header->ip_sum);

    // IP 주소 추출
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    ss << " src_ip=" << source_ip;
    ss << " dst_ip=" << dest_ip;
    str += ss.str();
    std::cout << "Source IP: " << source_ip << std::endl;
    std::cout << "Destination IP: " << dest_ip << std::endl;
    uint8_t protocol = ip_header->ip_p;

    if (protocol == IPPROTO_TCP) {
        return M_TCP;
    } else if (protocol == IPPROTO_UDP) {
        return M_UDP;
    } else {
        std::cout << "Unknown Protocol" << std::endl;
        return M_UNKNOWN;
    }
}

void dump_tcp_header(const u_char *pkt_data, std::string &str) {
    struct ip* ip_header = (struct ip*)(pkt_data + 14);
    std::ostringstream oss;

    // TCP 헤더 추출
    struct tcphdr* tcp_header = (struct tcphdr*)(pkt_data + 14 + ip_header->ip_hl * 4);

    // TCP 포트 번호 추출
    uint16_t source_port = ntohs(tcp_header->th_sport);
    uint16_t dest_port = ntohs(tcp_header->th_dport);

    oss << " src_port=" << source_port;
    oss << " dst_port=" << dest_port;
    oss << " protocol=tcp";
    str += oss.str();

    std::cout << "Source Port: " << source_port << std::endl;
    std::cout << "Destination Port: " << dest_port << std::endl;
}

void dump_udp_header(const u_char *pkt_data, std::string &str) {
    struct ip* ip_header = (struct ip*)(pkt_data + 14);
    struct udphdr* udp_header = (struct udphdr*)(pkt_data + 14 + ip_header->ip_hl * 4);

    std::ostringstream oss;
    // UDP 포트 번호 추출
    uint16_t source_port = ntohs(udp_header->uh_sport);
    uint16_t dest_port = ntohs(udp_header->uh_dport);

    oss << " src_port=" << source_port;
    oss << " dst_port=" << dest_port;
    oss << " protocol=udp";
    str += oss.str();

    std::cout << "Protocol: UDP" << std::endl;
    std::cout << "Source Port: " << source_port << std::endl;
    std::cout << "Destination Port: " << dest_port << std::endl;
}

// http 패킷인지 확인하는 부분 구현 후 사용
void dump_http_header(const u_char *pkt_data,  const struct pcap_pkthdr *header) {
    struct ip* ip_header = (struct ip*)(pkt_data + 14);
    struct tcphdr* tcp_header = (struct tcphdr*)(pkt_data + 14 + ip_header->ip_hl * 4);
    const u_char* payload = pkt_data + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
    int payload_length = header->len - (14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4);

    // HTTP 헤더 검사
    if (payload_length >= 4 && std::strncmp(reinterpret_cast<const char*>(payload), "HTTP", 4) == 0) {
        std::cout << "HTTP Packet" << std::endl;
        
        // HTTP 헤더와 본문 분리
        const char* http_data = reinterpret_cast<const char*>(payload);
        const char* double_newline = strstr(http_data, "\r\n\r\n");

        if (double_newline) {
            // HTTP 헤더와 본문 분리
            int header_length = double_newline - http_data + 4;
            std::string http_header(http_data, header_length);
            std::string http_body(double_newline + 4, payload_length - header_length);

            std::cout << "HTTP Header:\n" << http_header << std::endl;
            std::cout << "HTTP Body:\n" << http_body << std::endl;
        }
    }
}
```

## ethernet.h
```cpp
#pragma once
#include <sys/types.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <pcap.h>

#define M_TCP 6
#define M_UDP 8
#define M_UNKNOWN 0

void dump_ethernet_header(const u_char *pkt_data, std::string& str);
int dump_ip_header(const u_char *pkt_data, std::string& str);
void dump_tcp_header(const u_char *pkt_data, std::string &str);
void dump_udp_header(const u_char *pkt_data, std::string &str);
void dump_http_header(const u_char *pkt_data,  const struct pcap_pkthdr *header);
```

## myutil.cpp
```cpp
#include "myutil.h"

std::string getFileName()
{
    auto now = std::chrono::system_clock::now();

    std::time_t time = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm_time = *std::localtime(&time);
    std::ostringstream formatted_time;
    formatted_time << std::put_time(&tm_time, "%Y_%m_%d_%H_%M_%S.pcap");
    std::string current_time = formatted_time.str();

    return current_time;
}

std::string getFileData(int start, int len, const u_char *pkt_data) {
    auto *tmp = pkt_data+start;
    std::ostringstream ss;
    for (int i = start; i < len; i++) {
        ss << *tmp;
        tmp++;
    }

    return ss.str();
}

std::string getTimeStamp() {
    // 현재 시간 가져오기
    std::time_t currentTime = std::time(nullptr);
    std::tm* localTime = std::localtime(&currentTime);

    // 날짜와 시간 형식 지정
    std::string dateFormat = "date=%Y-%m-%d ";
    std::string timeFormat = "time=%H:%M:%S";

    // 날짜와 시간을 문자열로 변환
    char dateString[20];
    char timeString[20];

    std::strftime(dateString, sizeof(dateString), dateFormat.c_str(), localTime);
    std::strftime(timeString, sizeof(timeString), timeFormat.c_str(), localTime);

    std::stringstream ss;
    ss << dateString << timeString;

    return ss.str();
}
```

## makefile
```makefile
CXX = g++
CXXFLAGS = -Wall
LDFLAGS = -lpcap

SRC_DIR = ./src
OBJ_DIR = ./obj

TARGET = main

SRCS = $(notdir $(wildcard $(SRC_DIR)/*.cpp))
OBJS = $(SRCS:.cpp=.o)
OBJECTS = $(patsubst %.o,$(OBJ_DIR)/%.o,$(OBJS))
DEPS = $(OBJECTS:.o=.d)

all: $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ -MD $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(DEPS) $(TARGET) $(MODULES) *.pcap

.PHONY : all clean
```

# nestjs
- c++에서 소켓으로 보낸 로그를 mysql에 저장한다.

## logger.service.ts
```ts
import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm'
import * as dgram from 'dgram';
import { Raws } from 'src/models/raws.model';

@Injectable()
export class LoggerService {
    constructor(
        @InjectRepository(Raws)
        private readonly rawsRepository: Repository<Raws>
    ) {
        const server = dgram.createSocket('udp4');

        server.on('listening', () => {
            let address = server.address();
            console.log(`server is listening on ${address.address}:${address.port}`);
        });

        server.on('message',async (message, rinfo) => {
            let str = message.toString();
            console.log(str);
            let logObject: any = {};
            logObject['raw_data'] = str;
            await this.insertLog(logObject);
        });

        server.on('error', (error) => {
            console.log(error);
        });

        server.bind(514);
    }

    async insertLog(log: any) {
        const createdLog = this.rawsRepository.create(log);
        this.rawsRepository.save(createdLog)
        .catch( (error) => {
            console.log(error);
        });
    }

}
```

## logger.module.ts
```ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from "@nestjs/typeorm";
import { LoggerService } from "./logger.service";
import { Raws } from 'src/models/raws.model';


@Module({
    imports: [TypeOrmModule.forFeature([Raws])],
    providers: [LoggerService],
    controllers: [],
    exports: [LoggerService],
  })
  export class LoggerModule {}
```

## raws.model.ts
```ts
import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity({
    database: 'log'
})
export class Raws {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ type: 'varchar', length: 200 })
    raw_data: string;
}
```

## app.module.ts
```ts
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config'
import ormOptions from 'ormconfig';
import { LoggerModule } from './logger/logger.module';

@Module({
  imports: [
    LoggerModule,
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
    }),
    TypeOrmModule.forRoot(ormOptions)
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

## ormconfig.ts
```ts
import { TypeOrmModuleOptions } from "@nestjs/typeorm"
import { Raws } from "src/models/raws.model"

const ormOptions: TypeOrmModuleOptions = 
{
    "type": "mysql",
    "host": "localhost",
    "port": 3306,
    "username": "id",
    "password": "pw",
    "database": "dbname",
    "entities": [Raws],
    "synchronize": false
}

export default ormOptions
```

# mysql
- 저장된 로그 예시

![img](/assets/images/mysqllog.png)