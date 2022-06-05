#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bcc/BPF.h>
#include "tls_message.h"

void print_output(void* cb_cookie, void* data, int dataSize) {
  struct TLS_MESSAGE tlsMessage;
  memcpy(&tlsMessage, data, dataSize);

  printf("############### TLS MESSAGE ###########\r\n");
  printf("elapsed     -> %lu ms\r\n", (tlsMessage.elapsed/1000));
  printf("ptid        -> %lu\r\n", tlsMessage.ptid);
  printf("tls content:\r\n");
  printf("\r\n%s\r\n", tlsMessage.message);
  printf("\r\n");
}


char * loadProbeCode(char *probeFilePath) {
  FILE *probeFd;
  probeFd = fopen(probeFilePath, "r");
  if (probeFd == NULL) {
    printf("Loading probe file [%s] failed with error [%d]", probeFilePath, errno);
    exit(1);
  }

  fseek(probeFd, 0, SEEK_END);
  long probeFdSize = ftell(probeFd);

  char *probeFileContent = (char *)malloc(probeFdSize + 1);
  fseek(probeFd, 0, SEEK_SET);
  fread(probeFileContent, probeFdSize, 1, probeFd);

  fclose(probeFd);
  probeFileContent[probeFdSize] = 0;
  
  return probeFileContent;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    printf("Bad arguments. Expected [./tls_tracer <probe path> <binary path]");
    exit(1);
  }
  
  char *probePath = argv[1];
  char *binaryPath = argv[2];
  char *probeCode = loadProbeCode(probePath);

  
  ebpf::BPF bpfClient;
  ebpf::StatusTuple init_status = bpfClient.init(probeCode);
  if (init_status.code() != 0) {
    printf("Unable to initialize BCC BPF program. Failed with error [%d]", init_status.code());
    exit(1);
  }

  ebpf::StatusTuple returnSslReadStatus = bpfClient.attach_uprobe(binaryPath, "SSL_read", "uprobe_return_SSL_read", 0, BPF_PROBE_RETURN);
  if (returnSslReadStatus.code() != 0) {    
    printf("Failed to attach uprobe [%s] to binary [%s]. Failed with [%s].", probePath, binaryPath, returnSslReadStatus.msg().c_str());
    exit(1);
  }

  ebpf::StatusTuple entrySslReadStatus = bpfClient.attach_uprobe(binaryPath, "SSL_read", "uprobe_entry_SSL_read", 0, BPF_PROBE_ENTRY);
  if (entrySslReadStatus.code() != 0) {    
    printf("Failed to attach uprobe [%s] to binary [%s]. Failed with [%s].", probePath, binaryPath, entrySslReadStatus.msg().c_str());
    exit(1);
  }
  
  ebpf::StatusTuple returnSslWriteStatus = bpfClient.attach_uprobe(binaryPath, "SSL_write", "uprobe_return_SSL_write", 0, BPF_PROBE_RETURN);
  if (returnSslWriteStatus.code() != 0) {    
    printf("Failed to attach uprobe [%s] to binary [%s]. Failed with [%s].", probePath, binaryPath, returnSslWriteStatus.msg().c_str());
    exit(1);
  }

  ebpf::StatusTuple entrySslWriteStatus = bpfClient.attach_uprobe(binaryPath, "SSL_write", "uprobe_entry_SSL_write", 0, BPF_PROBE_ENTRY);
  if (entrySslWriteStatus.code() != 0) {    
    printf("Failed to attach uprobe [%s] to binary [%s]. Failed with [%s].", probePath, binaryPath, entrySslWriteStatus.msg().c_str());
    exit(1);
  }


  bpfClient.open_perf_buffer(PERF_BUFFER_NAME, &print_output, nullptr);
  ebpf::BPFPerfBuffer *buffer = bpfClient.get_perf_buffer(PERF_BUFFER_NAME);
  while (true) {
    buffer->poll(100);
  }

  return 0;
}
