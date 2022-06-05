#pragma once

#define MAX_DATA_SIZE 8192
#define PERF_BUFFER_NAME "TLS_DATA_PERF_OUTPUT"

struct TLS_MESSAGE {
  uint64_t elapsed;
  uint64_t ptid;
  char message[MAX_DATA_SIZE];
};