/* Mavericks port: no pointer authentication on Intel; make the macros no-ops. */
#ifndef MIP_COMPAT_PTRAUTH_H
#define MIP_COMPAT_PTRAUTH_H
#define ptrauth_strip(value, key) (value)
#define ptrauth_sign_unauthenticated(value, key, data) (value)
#define ptrauth_key_function_pointer 0
#define ptrauth_key_process_dependent_data 0
#endif
