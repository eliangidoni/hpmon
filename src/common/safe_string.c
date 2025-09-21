#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Safe string copy function that ensures null termination */
int safe_strcpy(char *dest, size_t dest_size, const char *src)
{
    if (!dest || !src || dest_size == 0) {
        return -1;
    }

    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        /* Truncate to fit */
        memcpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 1; /* Indicate truncation */
    }

    memcpy(dest, src, src_len + 1); /* Include null terminator */
    return 0;                       /* Success */
}

/* Safe formatted string function */
int safe_snprintf(char *dest, size_t dest_size, const char *format, ...)
{
    if (!dest || !format || dest_size == 0) {
        return -1;
    }

    va_list args;
    va_start(args, format);
    int result = vsnprintf(dest, dest_size, format, args);
    va_end(args);

    if (result < 0) {
        dest[0] = '\0'; /* Ensure null termination on error */
        return -1;
    }

    if (result >= (int)dest_size) {
        /* Truncation occurred, but dest is still null-terminated */
        return 1;
    }

    return 0; /* Success */
}

/* Safe string copy function with maximum length from source */
int safe_strncpy(char *dest, const char *src, size_t dest_size)
{
    if (!dest || !src || dest_size == 0) {
        return -1;
    }

    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        /* Truncate to fit */
        memcpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 1; /* Indicate truncation */
    }

    memcpy(dest, src, src_len + 1); /* Include null terminator */
    return 0;                       /* Success */
}
