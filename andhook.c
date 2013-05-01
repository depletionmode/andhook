#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#define LIB_PATH "/system/lib/"

void *__memcpy(void *d, void *s, int n)
{
    int i;

    for( i = 0; i < n; i++)
        ((unsigned char *)d)[i] = ((unsigned char *)s)[i];

    return d;
}

int __mprotect_no_errno_set(void * a, int n, int p)
{
#ifdef __arm__
    __asm__("mov R7, #0x7d");
    __asm__("svc 0x00");
    __asm__("bxpl LR");
#else
    return mprotect(a, n, p);
#endif
}

void __load_lib(char *ahp_path)
{
    void *handle;
    char *suffix;
    char lib_path[500];
    char *lib_name = strdup( ahp_path );

    /* convert to lib path */
    suffix = strrchr( lib_name, '.' );
    strcpy( suffix, ".so" );

    snprintf( lib_path, sizeof( lib_path ), "%s%s", LIB_PATH, lib_name );

    printf( "andhook: loading lib: %s\n", lib_path );

    /* open lib & exec __init() */
    if( ( handle = dlopen( lib_path, RTLD_NOW ) ) ) {
        printf( "andhook: lib loaded\n" );
        void (*p)() = dlsym( handle, "__init" );
        p();
        dlclose( handle );
    }

    free( lib_name );
}

char *__get_exec_name()
{
    static char exec_name[1024];
    char path[500];
    int pid, n;

    pid = getpid();

    snprintf( path, sizeof( path ), "/proc/%d/exe", pid );

    /* read symlink */
    n = readlink( path, exec_name, sizeof( exec_name ) - 1 );
    exec_name[n] = '\0';
    strcpy( exec_name, strrchr( exec_name, '/' ) + 1 );

    if( strcmp( exec_name, "app_process" ) ) {
        FILE *f;

        snprintf( path, sizeof( path ), "/proc/%d/cmdline", pid );

        if( ( f = fopen( path, "r" ) ) ) {
            n = fread( exec_name, 1, sizeof( exec_name ) - 1, f );
            exec_name[n] = '\0';

            fclose( f );
        }
    }

    return exec_name;
}

__attribute__((constructor))
void __init_framework()
{
    DIR *dp;
    struct dirent *dirp;
    int i;
    struct ahp_info_t *ahp_info_list = NULL;
    char *exec_name = strrchr( __get_exec_name(), '/' );
    
    if( !exec_name ) exec_name = __get_exec_name();
    else exec_name++;

    printf( "andhook: init (exec_name=%s)\n", exec_name );

    /* parse ahp files */
    if( ( dp = opendir( LIB_PATH ) ) ) {
        while( ( dirp = readdir( dp ) ) ) {
            char buf[1024];
            int mode;
            FILE *f_ahp;

            if( !strstr( dirp->d_name, ".ahp" ) ) continue;

            if( ( f_ahp = fopen( dirp->d_name, "r" ) ) ) {
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

                    printf( "andhook: parsed profile: %s (found=%d, mode=%s)\n", dirp->d_name, found, mode ? "include" : "exclude" );

                    if( found ) { if( mode /* include */ ) __load_lib(dirp->d_name); }
                    else { if( !mode /* exclude */ ) __load_lib(dirp->d_name); }
                }

            fclose( f_ahp );
            }
            }
        }
    }
}

void and_hook(void *orig_fcn, void* new_fcn, void **orig_fcn_ptr)
{
    printf( "andhook: placing hook (orig_fcn=%p, new_fcn=%p, orig_fcn_ptr=%p)\n", 
            orig_fcn,
            new_fcn,
            orig_fcn_ptr );

#ifdef __arm__
    unsigned char *hook = malloc( sysconf( _SC_PAGESIZE ) );

    __memcpy( hook, (unsigned char *)orig_fcn, 8 );    /* save 1st 8 bytes of orig fcn */
    *(int *)(hook + 8) = 0x04f01fe5;                   /* ldr pc, [pc, #-4] */
    *(int *)(hook + 12) = (int)orig_fcn + 8;           /* ptr to orig fcn offset */

    if( __mprotect_no_errno_set( (void *)(int)hook - ((int)hook % sysconf( _SC_PAGESIZE )),
                                 sysconf( _SC_PAGESIZE ),
                                 PROT_EXEC|PROT_READ ) == 0 ) {
        if( __mprotect_no_errno_set( (void *)((int)orig_fcn - ((int)orig_fcn % sysconf( _SC_PAGESIZE ))),
                                     (int)orig_fcn % sysconf( _SC_PAGESIZE ) + 8,
                                     PROT_READ|PROT_WRITE ) == 0 ) {
            *((unsigned int*)orig_fcn) = 0x04f01fe5;
            *((unsigned int*)((int)orig_fcn + 4)) = (int)new_fcn;

            if( __mprotect_no_errno_set( (void *)((int)orig_fcn - ((int)orig_fcn % sysconf( _SC_PAGESIZE ))),
                                         (int)orig_fcn % sysconf( _SC_PAGESIZE ) + 8,
                                         PROT_READ|PROT_EXEC ) == 0 ) {
                *orig_fcn_ptr = (void*)hook;
            }
        }
    }
#endif
}
