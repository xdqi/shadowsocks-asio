#include <cstdio>
#include <cstdarg>

void LOG(const char *level, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "[%-7s] [%s:%d] ", level, __PRETTY_FUNCTION__, __LINE__);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}