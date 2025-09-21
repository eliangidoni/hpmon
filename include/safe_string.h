#ifndef SAFE_STRING_H
#define SAFE_STRING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Safe string copy function that ensures null termination
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source string
 * @return 0 on success, 1 if truncated, -1 on error
 */
int safe_strcpy(char *dest, size_t dest_size, const char *src);

/**
 * Safe formatted string function
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param format Format string
 * @param ... Format arguments
 * @return 0 on success, 1 if truncated, -1 on error
 */
int safe_snprintf(char *dest, size_t dest_size, const char *format, ...);

/**
 * Safe string copy function with maximum length from source
 * @param dest Destination buffer
 * @param src Source string
 * @param dest_size Size of destination buffer
 * @return 0 on success, 1 if truncated, -1 on error
 */
int safe_strncpy(char *dest, const char *src, size_t dest_size);

#ifdef __cplusplus
}
#endif

#endif /* SAFE_STRING_H */
