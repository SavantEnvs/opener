/* AFL harness for OpENer's EtherNet/IP encapsulation flow. Same loop as upstream's in-tree
 * fuzzHandlePacketFlow (source/src/ports/POSIX/main.c): read one packet from stdin, zero-padded to
 * 512 bytes, and feed it to HandleReceivedExplictTcpData. Upstream's own AFL binary cannot be used as
 * is (it does not link, needs libcap and a real network interface, and skips the encapsulation and
 * socket-timer setup the network handler normally does), so the setup lives here.
 * Built with afl-clang-fast; run outside AFL it handles stdin once. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "opener_api.h"
#include "cipconnectionobject.h"
#include "cipethernetlink.h"
#include "ciptcpipinterface.h"
#include "doublylinkedlist.h"
#include "encap.h"
#include "generic_networkhandler.h"
#include "socket_timer.h"
#include "typedefs.h"

#define FUZZ_BUFFER_SIZE 512

int main(void) {
  uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
  uint8_t buff[FUZZ_BUFFER_SIZE];
  struct sockaddr_in from_address;
  int remaining_bytes = 0;
  ENIPMessage outgoing_message;

  DoublyLinkedListInitialize(&connection_list,
                             CipConnectionObjectListArrayAllocator,
                             CipConnectionObjectListArrayFree);
  SetDeviceSerialNumber(123456789);
  if (kEipStatusOk != CipStackInit(1)) {
    abort();
  }
  CipEthernetLinkSetMac(mac);
  GetHostName(&g_tcpip.hostname);
  g_tcpip.interface_configuration.ip_address = htonl(0xC0A8010A);
  g_tcpip.interface_configuration.network_mask = htonl(0xFFFFFF00);
  /* normally done by the network handler: sets the platform endianess and the session table;
   * the timer table likewise (NetworkHandlerInitialize) */
  EncapsulationInit();
  SocketTimerArrayInitialize(g_timestamps, OPENER_NUMBER_OF_SUPPORTED_SESSIONS);

  while (__AFL_LOOP(10000)) {
    memset(buff, 0, sizeof(buff));
    ssize_t received_size = read(STDIN_FILENO, buff, sizeof(buff));
    if (received_size <= 0) {
      continue;
    }
    memset(&from_address, 0, sizeof(from_address));
    remaining_bytes = 0;

    InitializeENIPMessage(&outgoing_message);
    HandleReceivedExplictTcpData(0, buff, (size_t) received_size, &remaining_bytes,
                                 (struct sockaddr *) &from_address,
                                 &outgoing_message);
  }
  return 0;
}
