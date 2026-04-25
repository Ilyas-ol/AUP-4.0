#ifndef AUP_SDK_H
#define AUP_SDK_H

#include <stddef.h>

#ifdef _WIN32
#define AUP_SDK_EXPORT __declspec(dllexport)
#else
#define AUP_SDK_EXPORT
#endif

#ifdef __cplusplus
extern "C"
{
#endif

// Return codes.
#define SDK_OK 0
#define SDK_INVALID_LICENSE 1
#define SDK_CONSTRAINT_FAILED 2
#define SDK_INTERNAL_ERROR 3

    AUP_SDK_EXPORT int sdk_verify_license_json(
        const char *license_json,
        const char *public_key_b64,
        const char *today,
        unsigned int requested_users,
        const char *requested_modules_csv,
        const char *machine_binding);

    // Writes the last error message into the buffer.
    // Returns required length including null terminator.
    AUP_SDK_EXPORT size_t sdk_last_error(char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif
