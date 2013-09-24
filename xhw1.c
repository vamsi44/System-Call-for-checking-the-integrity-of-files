#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "xstructs.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define __NR_xintegrity 349     /* our private syscall number */

int main(int argc, char *argv[])
{
        int rc;
        int i=0;
        int mode = atoi(argv[1]);

        if(mode==1 || mode==2 || mode==3)
        {
            
        if(mode==1)
        {

        struct mode1args args1;

        args1.ibuf= (unsigned char *)malloc(16);
        bzero(args1.ibuf,16);
        args1.ilen=16;
        args1.flag= atoi(argv[1]);
        args1.filename= argv[2];// check for ilen
                
        rc = syscall(__NR_xintegrity,(void *) &args1);

 
        if (rc == 0)
        {
        
            printf("\n syscall returned %d\n", rc);
            printf("the values returned for ibuffer are ");
            for(i=0;i<16;i++)
                printf("%x",args1.ibuf[i]);
            printf("\n");
        }
    
        else
                printf("\n syscall returned %d (errno=%d)\n", rc, errno);

        exit(rc);

        }

        else if(mode==2)
        {

            struct mode2args args2;
            args2.flag= atoi(argv[1]);
            args2.filename= argv[2];
            args2.clen=-1;
            args2.ibuf= (unsigned char *)malloc(16); // check for crdential buff and clen and ilen
            bzero(args2.ibuf,16);
            args2.ilen =16;
            args2.credbuf= argv[3];
            
            if(args2.credbuf!=NULL)
                args2.clen= strlen(argv[3]);
           

        rc = syscall(__NR_xintegrity,(void *) &args2);

       
        if (rc == 0)
        {
            printf("\nsyscall returned %d\n", rc);
            printf("the values returned for ibuffer are : ");
            for(i=0;i<16;i++)
                printf("%x",args2.ibuf[i]);
            printf("\n");
        }

        else
                printf("\nsyscall returned %d (errno=%d)\n", rc, errno);

        exit(rc);
        
        }

        else if(mode==3)
        {
            struct mode3args args3;
            printf("%d %d \n",O_CREAT,O_TRUNC);
            args3.flag= atoi(argv[1]);
            args3.filename= argv[2];
            args3.oflag= -1;
            if(argv[3]!=NULL)
                args3.oflag = atoi(argv[3]);
            
               args3.mode = atoi(argv[4]);
             
         
        rc = syscall(__NR_xintegrity,(void *) &args3);

        if (rc == 0)
                printf("\nsyscall returned %d\n", rc);
        else
                printf("\nsyscall returned %d (errno=%d)\n", rc, errno);

        exit(rc);
        
        }

        else
        {
            printf("Please enter the correct mode while giving command line arugments \n");
            return -1;
        }

        }

        return 0;
}
