/* andhook - Android Hooking Framework */
/* David Kaplan, 2010 (david@2of1.org) */

/* Tested on Android 2.3.6, kernel 2.6.32 */

/* use this fcn within your library's __init() to set up hook */
void and_hook(void *orig_fcn, void* new_fcn, void **orig_fcn_ptr);
