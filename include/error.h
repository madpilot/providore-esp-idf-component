#ifndef _PROVIDORE_ERROR_h
#define _PROVIDORE_ERROR_h
typedef enum _providore_err
{
  PROVIDORE_OK = 0,
  PROVIDORE_SIG_MISMATCH = 1 << 0,
  PROVIDORE_FIRMWARE_FAIL = 1 << 1
} providore_err_t;
#endif