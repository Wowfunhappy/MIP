#include <mach/mach_types.h>
kern_return_t inject_to_task(mach_port_t task, const char *argument);
kern_return_t inject_to_task_thread(mach_port_t task, mach_port_t thread, const char *argument);
kern_return_t get_thread_port_for_task(mach_port_t task, mach_port_t *thread);

/* Mavericks port: used by `inject` to verify and catch up (see inject.c). */
#include <stdbool.h>
#include <sys/types.h>
bool task_has_image(mach_port_t task, const char *path);
bool thread_is_in_mach_msg(mach_port_t thread);
bool process_is_setugid(pid_t pid);
