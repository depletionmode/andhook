#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <glob.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

//#define LIB_PATH "/system/lib/"
#define LIB_PATH ""

extern char *program_invocation_name;

void *__memcpy(void *d, void *s, int n)
{
    int i;

    for( i = 0; i < n; i++)
        ((unsigned char *)d)[i] = ((unsigned char *)s)[i];

    return d;
}

int __mprotect(void * a, int n, int p)
{
    __asm__("mov R7, #0x7d");
    __asm__("svc 0x00");
    __asm__("bxpl LR");
}

void __load_lib(char *ahp_path)
{
    void *handle;
    char *suffix;
    char *lib_path = strdup( ahp_path );

    /* convert to lib path */
    suffix = strrchr( lib_path, '.' );
    strcpy( suffix, ".so" );

    /* open lib & exec __init() */
    if( ( handle = dlopen( lib_path, RTLD_NOW ) ) ) {
        void (*p)() = dlsym( handle, "__init" );
        p();
        dlclose( handle );
    }

    free( lib_path );
}

__attribute__((constructor))
void __init_framework()
{
    int i;
    glob_t glob_data;
    struct ahp_info_t *ahp_info_list = NULL;
    char *exec_name = strrchr( program_invocation_name, '/' );

    if( !exec_name ) exec_name = program_invocation_name;
    else exec_name++;

    /* parse ahp files */
    if( glob( LIB_PATH "*.ahp", 0, NULL, &glob_data ) == 0 ) {
        for( i = 0; i < glob_data.gl_pathc; i++ ) {
            char buf[1024];
            int mode;
            FILE *f_ahp = fopen( glob_data.gl_pathv[i], "r" );

            if( fgets( buf, sizeof(buf), f_ahp ) ) {
                if( memcmp( buf, "include=", 8 ) == 0 )
                    mode = 1;     /* include */
                else if( memcmp( buf, "exclude=", 8 ) == 0 )
                    mode = 0;     /* exclude */

                if( mode > -1 ) {
                    int found = 0;
                    char *tok = strtok( buf + 8, "," );

                    while( tok != NULL ) {
                        if( exec_name && strcmp( tok, exec_name ) == 0 ) {
                            found = 1;
                            break;
                        }

                        tok = strtok( NULL, "," );
                    }

                    if( found ) { if( mode /* include */ ) __load_lib(glob_data.gl_pathv[i]); }
                    else { if( !mode /* exclude */ ) __load_lib(glob_data.gl_pathv[i]); }
                }

            fclose( f_ahp );
            }
        }
    }
}

void and_hook(void *orig_fcn, void* new_fcn, void **orig_fcn_ptr)
{
    unsigned char *hook = malloc( sysconf( _SC_PAGESIZE ) );

    __memcpy( hook, (unsigned char *)orig_fcn, 8 );    /* save 1st 8 bytes of orig fcn */
    *(int *)(hook + 8) = 0xe51ff004;                   /* ldr pc, [pc, #-4] */
    *(int *)(hook + 12) = (int)orig_fcn + 8;           /* ptr to orig fcn offset */

    if( __mprotect( (void *)(int)hook - ((int)hook % sysconf( _SC_PAGESIZE )),
                      sysconf( _SC_PAGESIZE ),
                      PROT_EXEC|PROT_READ ) == 0 ) {
        if( __mprotect( (void *)((int)orig_fcn - ((int)orig_fcn % sysconf( _SC_PAGESIZE ))),
                        (int)orig_fcn % sysconf( _SC_PAGESIZE ) + 8,
                        PROT_READ|PROT_WRITE ) == 0 ) {
            *((unsigned int*)orig_fcn) = 0xe51ff004;
            *((unsigned int*)((int)orig_fcn + 4)) = (int)new_fcn;
            if( __mprotect( (void *)((int)orig_fcn - ((int)orig_fcn % sysconf( _SC_PAGESIZE ))),
                            (int)orig_fcn % sysconf( _SC_PAGESIZE ) + 8,
                            PROT_READ|PROT_EXEC ) == 0 )
                                *orig_fcn_ptr = (void*)hook;
        }
    }
}

int main() { return 0; }
