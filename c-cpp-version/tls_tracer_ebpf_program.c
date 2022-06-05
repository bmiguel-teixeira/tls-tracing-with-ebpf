#include <linux/ptrace.h>
#include "tls_message.h"

//https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps
BPF_PERF_OUTPUT(TLS_DATA_PERF_OUTPUT);

BPF_HASH(read_tls_map_data, u64, const char *);
BPF_HASH(read_tls_map_timestamp, u64, u64);

BPF_HASH(write_tls_map_data, u64, const char *);
BPF_HASH(write_tls_map_timestamp, u64, u64);

BPF_PERCPU_ARRAY(tls_data_array, struct TLS_MESSAGE);

static u32 getProcessID(u64 ptID) {
  // As per the docs, PID is in the  lower 32 bits.
  return  ptID >> 32;
}

static u32 getThreadID(u64 ptID) {
  // As per the docs, TID is in the  upper 32 bits.
  return  ptID << 32;
}

static int output_tls_message(struct pt_regs* ctx, u32 bufferLen, u64 id, const char * buffer) {
  u32 zeroPointer = 0;
  struct TLS_MESSAGE* tlsMessage = tls_data_array.lookup(&zeroPointer);
  if (tlsMessage == NULL) {
    return 0;
  }

  tlsMessage->ptid = id;
  u64 *et = read_tls_map_timestamp.lookup(&id);
  if (et == NULL) {
    return 0;
  }

  tlsMessage->elapsed = bpf_ktime_get_ns() - *et;

  u32 outputBufferLen = MAX_DATA_SIZE;
  if (bufferLen < MAX_DATA_SIZE) {
    outputBufferLen = bufferLen;
  }

  bpf_probe_read(tlsMessage->message, outputBufferLen, buffer);

  TLS_DATA_PERF_OUTPUT.perf_submit(ctx, tlsMessage, sizeof(*tlsMessage));
  read_tls_map_data.delete(&id);
  read_tls_map_timestamp.delete(&id);

  return 0;
}


int uprobe_entry_SSL_write(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  const char* buffer = (const char*)PT_REGS_PARM2(ctx);
  write_tls_map_timestamp.update(&processThreadID, &ts);
  write_tls_map_data.update(&processThreadID, &buffer);

  return 0;
}

int uprobe_return_SSL_write(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();

  const char** buffer = write_tls_map_data.lookup(&processThreadID);
  if (buffer != NULL) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
      return 0;
    }

    output_tls_message(ctx, len, processThreadID, *buffer);
  }

  return 0;
}

int uprobe_entry_SSL_read(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  const char* buffer = (const char*)PT_REGS_PARM2(ctx);
  read_tls_map_timestamp.update(&processThreadID, &ts);
  read_tls_map_data.update(&processThreadID, &buffer);

  return 0;
}

int uprobe_return_SSL_read(struct pt_regs* ctx) {
  u64 processThreadID = bpf_get_current_pid_tgid();

  const char** buffer = read_tls_map_data.lookup(&processThreadID);
  if (buffer != NULL) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
      return 0;
    }

    output_tls_message(ctx, len, processThreadID, *buffer);
  }

  return 0;
}

