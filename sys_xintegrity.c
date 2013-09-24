#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include "xstructs.h"
#include <linux/types.h>
#include <linux/file.h>
#include <linux/string.h>

asmlinkage extern long (*sysptr)(void *arg);



asmlinkage long xintegrity(void *arg)
{

    int retval,retval1,retval2,retval3;
    int retval_check;
    struct mode1args *args1;
    struct mode2args *args2;
    struct mode3args *args3;
    struct file *fp;
    struct file *f;
    mm_segment_t oldfs;
    unsigned char *checkmode;
    char * pwd="vamsivaranasi";
    struct scatterlist sg[1];
    char *rbuf;
    int rc;
    int nbytes;
    char *digest=NULL;
    loff_t i_size;
    int i;
    int fd;
    unsigned char *buff=NULL;
    struct hash_desc desc;

        if(arg==NULL)
        return -EINVAL;


    if(!access_ok(VERIFY_READ,arg,sizeof(unsigned char)))
    {
        printk("access_ok error for flag \n");
        return -EACCES;
    }

    else
      checkmode=kmalloc(sizeof(unsigned char), GFP_KERNEL);


    if(checkmode==NULL)
        return -ENOMEM;

    retval_check=copy_from_user(checkmode,arg,sizeof(unsigned char));

    if(retval_check!=0)
    {
        printk("Error in copy_from_user for the flag\n");
        kfree(checkmode);
        return -EINVAL;
    }
 
    if((*checkmode)==1)
    {
       
    printk("Entering the mode 1 \n");
    retval=access_ok(VERIFY_READ,(struct mode1args *)arg,sizeof(struct mode1args));

    if(retval==0)
    {
        printk("access_ok returned error for struct ptr \n");
        kfree(checkmode);
        return -EACCES;
    }

    else
        args1=kmalloc(sizeof(struct mode1args), GFP_KERNEL);

    if(args1==NULL)
        return -ENOMEM;

    if(((struct mode1args *)arg)->filename==NULL )
    {
        printk("Invalid Filename \n");
        kfree(args1);
        return -EINVAL;
    }

    if(!((struct mode1args *)arg)->ilen)
    {
        printk("Invalid length for the buffer \n");
        kfree(args1);
        return -EINVAL;
    }

    retval1=copy_from_user(args1,(struct mode1args *)arg,sizeof(struct mode1args));

    if(retval1!=0)
    {
        printk("Error in copy_from_user for structure \n");
        kfree(args1);
        kfree(checkmode);
        return -EINVAL;
    }

    if(!access_ok(VERIFY_READ,((struct mode1args *)arg)->filename,strlen(((struct mode1args *)arg)->filename)))
    {
        printk("access_ok error for file ptr \n");
        kfree(args1);
        kfree(checkmode);
        return -EACCES;
    }
    else
        args1->filename=getname(((struct mode1args *)arg)->filename);


    if(args1->filename==NULL)
    {
        printk("Error in getname for the given filename \n");
        kfree(args1);
        kfree(checkmode);
        return -EFAULT;
    }

    if (!access_ok(VERIFY_WRITE,((struct mode1args *)arg)->ibuf,((struct mode1args *)arg)->ilen))
    {
        printk("access_ok error for ibuffer in mode1 \n");
        putname(args1->filename);
        kfree(args1);
        kfree(checkmode);
        return -EACCES;
    }
    else
        args1->ibuf=kmalloc(((struct mode1args *)arg)->ilen,GFP_KERNEL);

    if(args1->ibuf==NULL)
    {
        printk("Memory allocation error for ibuf \n");
        putname(args1->filename);
        kfree(args1);
        kfree(checkmode);
        return -ENOMEM;
    }

    if(copy_from_user(args1->ibuf,((struct mode1args *)arg)->ibuf,((struct mode1args *)arg)->ilen))
    {
        printk("Error in copy_from_user for ibuffer \n");
        kfree(args1->ibuf);
        putname(args1->filename);
        kfree(args1);
        kfree(checkmode);
        return -EINVAL;
    }

    fp = filp_open(args1->filename, O_RDONLY, 0);

    if (!fp || IS_ERR(fp))
    {
        putname(args1->filename);
        kfree(args1->ibuf);
        kfree(args1);
        kfree(checkmode);
        printk("wrapfs_read_file err %d\n", (int) PTR_ERR(fp));
        return -1;  /* or do something else */
    }


     if(!fp->f_op->read)
     {

            printk("the user doesn't have permission to read on the file system doesn't allow reads \n");
            putname(args1->filename);
            kfree(args1->ibuf);
            kfree(args1);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -2;
     }

        

    retval2= vfs_getxattr(fp->f_path.dentry,"user.md5sumcheck",args1->ibuf,((struct mode1args *)arg)->ilen);

    if(retval2<=0)
    {
        printk("The attribute doesn't exist \n");
        putname(args1->filename);
        kfree(args1->ibuf);
        kfree(args1);
        kfree(checkmode);
        filp_close(fp, NULL);
        return -EFAULT;
    }


    if(copy_to_user(((struct mode1args *)arg)->ibuf,args1->ibuf,strlen(args1->ibuf)))
    {
        printk("error in copy_to_user in mode1 \n");
        putname(args1->filename);
        kfree(args1->ibuf);
        kfree(args1);
        kfree(checkmode);
        filp_close(fp, NULL);
        return -EINVAL;
    }

    else
    {
        printk("the value of the ibuffer is copied from kernel to user and value is ");
        for(i=0;i<strlen(args1->ibuf);i++)
        printk("%x",args1->ibuf[i]);
        putname(args1->filename);
        kfree(args1->ibuf);
        kfree(args1);
        kfree(checkmode);
        filp_close(fp, NULL);
        return 0;
    }

}
    else if((*checkmode)==2)
    {
       
        retval=access_ok(VERIFY_READ,(struct mode2args *)arg,sizeof(struct mode2args));

        if(retval==0)
        {
            printk("access_ok returned error for struct ptr in mode2 \n");
            kfree(checkmode);
            return -EACCES;
        }

        else
            args2=kmalloc(sizeof(struct mode2args), GFP_KERNEL);

        if(args2==NULL)
            return -ENOMEM;



    if(((struct mode2args *)arg)->filename==NULL)
    {
        printk("Invalid Filename \n");
        kfree(args2);
        return -EINVAL;
    }

    if(((struct mode2args *)arg)->ilen<=0)
    {
        printk("Invalid Length for the buffer \n");
        kfree(args2);
        return -EINVAL;
    }

    if(((struct mode2args *)arg)->credbuf==NULL)
    {
        printk("Invalid Buffer \n");
        kfree(args2);
        return -EINVAL;
    }

    if(((struct mode2args *)arg)->clen<=0)
    {
        printk("Invalid length for cred buffer \n");
        kfree(args2);
        return -EINVAL;
    }

       
        retval1=copy_from_user(args2,(struct mode2args *)arg,sizeof(struct mode2args));

        if(retval1!=0)
        {
            printk("Error in copy_from_user for structure in mode2 \n");
            kfree(args2);
            kfree(checkmode);
            return -EINVAL;// check for kfree
        }

        if(!access_ok(VERIFY_READ,((struct mode2args *)arg)->filename,strlen(((struct mode2args *)arg)->filename)))
        {
            printk("access_ok error for file ptr in mode2\n");
            kfree(args2);
            kfree(checkmode);
            return -EACCES;
        }

        else
            args2->filename=getname(((struct mode2args *)arg)->filename);


        if(args2->filename==NULL)
        {
            printk("Error in getname (filename) in mode 2 \n");
            kfree(args2);
            kfree(checkmode);
            return -EFAULT;
        }


       
        if (!access_ok(VERIFY_WRITE,((struct mode2args *)arg)->ibuf,((struct mode2args *)arg)->ilen))
        {
            printk("access_ok error for ibuffer in mode2 \n");
            putname(args2->filename);
            kfree(args2);
            kfree(checkmode);
            return -EACCES;
        }
        else
            args2->ibuf=kmalloc(((struct mode2args *)arg)->ilen,GFP_KERNEL);

        if(args2->ibuf==NULL)
        {
            printk("Memory not allocated to IBUF in mode 2 \n");
            putname(args2->filename);
            kfree(args2);
            kfree(checkmode);
            return -ENOMEM;
        }

        if(copy_from_user(args2->ibuf,((struct mode2args *)arg)->ibuf,((struct mode2args *)arg)->ilen))
        {
            printk("Error in copy_from_user for ibuffer in mode2\n");
            kfree(args2->ibuf);
            putname(args2->filename);
            kfree(args2);
            kfree(checkmode);
            return -EINVAL;// check for kfree
        }

       
        if (!access_ok(VERIFY_READ,((struct mode2args *)arg)->credbuf,strlen(((struct mode2args *)arg)->credbuf)))
        {
            printk("access_ok error for credbuffer in mode 2\n");
            putname(args2->filename);
            kfree(args2);
            kfree(checkmode);
            return -EACCES;
        }
        else
            args2->credbuf= getname(((struct mode2args *)arg)->credbuf);
        

        if(args2->credbuf==NULL)
        {
            putname(args2->filename);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            return -ENOMEM;
        }
        

        if(strcmp(pwd,args2->credbuf))
        {
            printk("Passwords do not match \n");
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            return -EPERM;
        }

        fp = filp_open(args2->filename, O_RDONLY, 0);

        if (!fp || IS_ERR(fp))
        {
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            printk("wrapfs_read_file err %d\n", (int) PTR_ERR(fp));
            return -1;  /* or do something else */
        }


        if(!fp->f_op->write)
         {

            printk("the user doesn't have permission to read/write on the file system doesn't allow reads \n");
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -2;

         }        
       
        fp->f_pos= 0;
        oldfs = get_fs();
        set_fs(KERNEL_DS);


                desc.tfm = crypto_alloc_hash("md5",0,0x00000080);

                if(IS_ERR(desc.tfm))
                {
                    rc=PTR_ERR(desc.tfm);
                    printk("Error attempting to allocate crypto context l rc = %d \n",rc);
                    return rc;
                }

                desc.flags=0;  

                rc=crypto_hash_init(&desc);

           if(rc)
           {
                printk("Error initializing crypto hash ; rc= %d \n",rc);
                crypto_free_hash(desc.tfm);
                putname(args2->filename);
                putname(args2->credbuf);
                kfree(args2->ibuf);
                kfree(args2);
                kfree(checkmode);
                filp_close(fp, NULL);
                return rc;
           }

       
        rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);

        if(!rbuf)
        {
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -ENOMEM;
        }
       
        i_size = i_size_read(fp->f_dentry->d_inode);
        
    
        while(fp->f_pos<i_size)
        {

           nbytes=fp->f_op->read(fp,rbuf,PAGE_SIZE,&fp->f_pos);
           
           if(nbytes<0)
           {
               rc= nbytes;
               break;
           }

           if(nbytes==0)
                break;
        
           fp->f_pos+=nbytes;
           sg_init_one(sg,rbuf,nbytes);
           rc= crypto_hash_update(&desc,sg,nbytes);
            
           if(rc)
           {
                printk("Error updating crypto hash ; rc= %d \n",rc);
                crypto_free_hash(desc.tfm);
                putname(args2->filename);
                putname(args2->credbuf);
                kfree(args2->ibuf);
                kfree(args2);
                kfree(rbuf);
                kfree(checkmode);
                filp_close(fp, NULL);
                return rc;
           }
        }
    
        kfree(rbuf);
    
        digest=kmalloc(16,GFP_KERNEL);

        if(digest==NULL)
        {
            printk("Memory not allocated to IBUF in mode 2 \n");
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -ENOMEM;
        }

           rc=crypto_hash_final(&desc,digest);
       
        if(rc)
        {
            printk("Error finalizing crypto hash ; rc= %d \n",rc);
            return rc;
        }

        retval2= vfs_setxattr(fp->f_path.dentry,"user.md5sumcheck",digest,16,0);

        if(retval2<0)
        {
            printk("Error in setting attributes \n");
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            kfree(digest);
            filp_close(fp, NULL);
            return retval2;
        }


        retval3= vfs_getxattr(fp->f_path.dentry,"user.md5sumcheck",args2->ibuf,((struct mode2args *)arg)->ilen);

        if(retval3<=0)
        {
            printk("Error in getting attributes \n");
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            kfree(digest);
            filp_close(fp,NULL);
            return -EFAULT;
        }
        else
            printk("the number of bytes in ibuffer is %d \n ",retval3);
    


        if(copy_to_user(((struct mode2args *)arg)->ibuf,args2->ibuf,strlen(args2->ibuf)))
        {
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            kfree(digest);
            filp_close(fp,NULL);
            return -EINVAL;
        }

        else
        {
            printk("the value of the ibuffer is copied from kernel to user and value is :");
            for(i=0;i<strlen(args2->ibuf);i++)
            printk("%x",((struct mode2args *)arg)->ibuf[i]);
            putname(args2->filename);
            putname(args2->credbuf);
            kfree(args2->ibuf);
            kfree(args2);
            kfree(checkmode);
            kfree(digest);
            filp_close(fp, NULL);
            return 0;
        }

    }
        else if((*checkmode)==3) 
        {
        
        
        retval=access_ok(VERIFY_READ,(struct mode3args *)arg,sizeof(struct mode3args));

        if(retval==0)
        {
            printk("access_ok returned error for struct ptr in mode2 \n");
            kfree(checkmode);
            return -EACCES;
        }

        else
            args3=kmalloc(sizeof(struct mode3args), GFP_KERNEL);

        if(args3==NULL)
            return -ENOMEM;


        if(((struct mode3args *)arg)->filename==NULL)
        {
            printk("Invalid arguments \n");
            kfree(args3);
            return -EINVAL;
        }

        if(((struct mode3args *)arg)->oflag<0)
        {
            printk("Invalid flag \n");
            kfree(args3);
            return -EINVAL;   
        }


        retval1=copy_from_user(args3,(struct mode3args *)arg,sizeof(struct mode3args));

        if(retval1!=0)
        {
            printk("Error in copy_from_user for structure in mode3 \n");
            kfree(args3);
            kfree(checkmode);
            return -EINVAL;// check for kfree
        }

        if(!access_ok(VERIFY_READ,((struct mode3args *)arg)->filename,strlen(((struct mode3args *)arg)->filename)))
        {
            printk("access_ok error for file ptr in mode3\n");
            kfree(args3);
            kfree(checkmode);
            return -EACCES;
        }

        else
            args3->filename=getname(((struct mode3args *)arg)->filename);


        if(args3->filename==NULL)
        {
            printk("filename error in mode 3 \n");
            kfree(args3);
            kfree(checkmode);
            return -EFAULT;
        }

        fp = filp_open(args3->filename, O_RDONLY, 0);

        if (!fp || IS_ERR(fp))
        {

            if((((struct mode3args *)arg)->oflag & 64)==64)
            {
                printk("Entering mode create \n");
                goto Label;
            }
            else
            {
            putname(args3->filename);
            //kfree(args1->ibuf);
            kfree(args3);
            kfree(checkmode);
            filp_close(fp, NULL);
            printk("wrapfs_read_file err %d\n", (int) PTR_ERR(fp));
            return -1; 
            }
        }
        else
            buff=kmalloc(16, GFP_KERNEL);

        if(buff==NULL)
            return -ENOMEM;

        if(!fp->f_op->write)
        {

            printk("the user doesn't have permission to read/write on the file system doesn't allow reads \n");
            putname(args3->filename);
            kfree(buff);
            kfree(args3);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -2;
        }  


        retval2= vfs_getxattr(fp->f_path.dentry,"user.md5sumcheck",buff,16);

        if(retval2<=0)
        {
            printk("error in fetching attribute for the given file \n");
            putname(args3->filename);
            kfree(buff);
            kfree(args3);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -EFAULT;
        }

      
         
        fp->f_pos= 0;
        oldfs = get_fs();
        set_fs(KERNEL_DS);

                desc.tfm = crypto_alloc_hash("md5",0,0x00000080);

                if(IS_ERR(desc.tfm))
                {
                    rc=PTR_ERR(desc.tfm);
                    printk("Error attempting to allocate crypto context l rc = %d \n",rc);
                    return rc;
                }

                desc.flags=0;  
            
           rc=crypto_hash_init(&desc);

           if(rc)
           {
                printk("Error initializing crypto hash ; rc= %d \n",rc);
                crypto_free_hash(desc.tfm);
                return rc;
           }

        rbuf=kzalloc(PAGE_SIZE,GFP_KERNEL);

        if(!rbuf)
        {
            putname(args3->filename);
            kfree(buff);
            kfree(args3);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -ENOMEM;
        }
       
        i_size = i_size_read(fp->f_dentry->d_inode);
        
    
        while(fp->f_pos<i_size)
        {

           nbytes=fp->f_op->read(fp,rbuf,PAGE_SIZE,&fp->f_pos);
           
           if(nbytes<0)
           {
               rc= nbytes;
               break;
           }

           if(nbytes==0)
                break;
        
           fp->f_pos+=nbytes;
       
           sg_init_one(sg,rbuf,nbytes);
        
           rc= crypto_hash_update(&desc,sg,nbytes);
            
           if(rc)
           {
                printk("Error updating crypto hash ; rc= %d \n",rc);
                return rc;
           }
        }
    
        kfree(rbuf);
    
        digest=kmalloc(16,GFP_KERNEL);

        if(digest==NULL)
        {
            printk("Memory not allocated to IBUF in mode 2 \n");
            putname(args3->filename);
            kfree(buff);
            kfree(args3);
            kfree(checkmode);
            filp_close(fp, NULL);
            return -ENOMEM;
        }

           rc=crypto_hash_final(&desc,digest);
           filp_close(fp, NULL);

    
        if(rc)
        {
            printk("Error finalizing crypto hash ; rc= %d \n",rc);
            return rc;
        }
     
        if(memcmp(buff,digest,16)==0)
        {
        
        printk("the md5 check sum values match hence returning the file descriptor to the user \n");
Label:  
        fd = get_unused_fd();
        f = filp_open(args3->filename, args3->oflag, args3->mode);
        printk("arg3 : %d args mode %d ", args3->oflag, args3->mode);
        fd_install(fd, f);
        putname(args3->filename);
        kfree(buff);
        kfree(args3);
        kfree(checkmode);
        kfree(digest);
        return fd;
        }

        else
        {
            printk("the md5 check sum values donot match so returning error to user \n");
            putname(args3->filename);
            kfree(buff);
            kfree(args3);
            kfree(checkmode);
            kfree(digest);
            return -EPERM;
        }
        
    }

        return 0;

}


static int __init init_sys_xintegrity(void)
{
        printk("installed new sys_xintegrity module\n");
        if (sysptr == NULL)
                sysptr = xintegrity;
        return 0;
}
static void  __exit exit_sys_xintegrity(void)
{
        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_xintegrity module\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");


