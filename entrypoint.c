#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "http.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shpilkov Ilya");
MODULE_VERSION("0.01");

#define RELEASE
#ifdef RELEASE
#define printk(fmt, ...) ;
#endif

struct inode_operations networkfs_inode_ops;
struct file_operations networkfs_dir_ops;
struct file_operations networkfs_file_ops;

char tohex(char c) {
  if (c < 10) {
    return '0' + c;
  } else {
    return 'a' + c - 10;
  }
}

char *encode_symbol(char c) {
  static char ans[4];
  ans[0] = '%';
  ans[1] = tohex(c / 16);
  ans[2] = tohex(c % 16);
  ans[3] = 0;
  return ans;
}

char *encode_url_query(const char *query, size_t len) {
  char *encoded = kzalloc(3 * len + 1, GFP_KERNEL);

  for (size_t i = 0; i < len; i++) {
    strcat(encoded, encode_symbol(query[i]));
  }

  return encoded;
}

struct inode *networkfs_get_inode(struct super_block *sb,
                                  const struct inode *dir, umode_t mode,
                                  int i_ino) {
  struct inode *inode;
  inode = new_inode(sb);
  if (inode != NULL) {
    inode->i_ino = i_ino;
    inode_init_owner(&init_user_ns, inode, dir, mode);

    inode->i_op = &networkfs_inode_ops;

    if (mode & S_IFDIR) inode->i_fop = &networkfs_dir_ops;
    if (mode & S_IFREG) inode->i_fop = &networkfs_file_ops;
  }
  return inode;
}

struct dentry *networkfs_lookup(struct inode *parent_inode,
                                struct dentry *child_dentry,
                                unsigned int flag) {
  printk(KERN_INFO "lookup to %s\n", child_dentry->d_name.name);
  ino_t root;
  struct inode *inode;
  char *name =
      encode_url_query(child_dentry->d_name.name, child_dentry->d_name.len);
  root = parent_inode->i_ino;
  char inode_id[20];
  sprintf(inode_id, "%ld", root);
  struct networkfs_entry_info entry_info;
  int rc = networkfs_http_call(
      parent_inode->i_sb->s_fs_info, "lookup", (void *)&entry_info,
      sizeof(struct networkfs_entry_info), 2, "parent", inode_id, "name", name);

  if (rc != 0) {
    kfree(name);
    return NULL;
  }

  umode_t mode = entry_info.entry_type == DT_DIR ? S_IFDIR : S_IFREG;
  inode = networkfs_get_inode(parent_inode->i_sb, parent_inode, mode | 0777,
                              entry_info.ino);
  d_add(child_dentry, inode);
  kfree(name);
  return NULL;
}

int networkfs_generic_create(struct user_namespace *ns,
                             struct inode *parent_inode,
                             struct dentry *child_dentry, umode_t mode) {
  printk(KERN_INFO "try create name: %s\n", child_dentry->d_name.name);

  ino_t root;
  struct inode *inode;
  root = parent_inode->i_ino;

  char *name =
      encode_url_query(child_dentry->d_name.name, child_dentry->d_name.len);

  ino_t new_inode;
  const char *type = mode & S_IFREG ? "file" : "directory";
  char parent_inode_id[20];
  sprintf(parent_inode_id, "%ld", root);
  int rc = networkfs_http_call(
      (const char *)parent_inode->i_sb->s_fs_info, "create", (void *)&new_inode,
      sizeof(ino_t), 3, "parent", parent_inode_id, "name", name, "type", type);

  if (rc < 0) {
    printk(KERN_ERR "create failed: %d\n", rc);
    kfree(name);
    return rc;
  }

  inode = networkfs_get_inode(parent_inode->i_sb, NULL, mode | 0777, new_inode);
  d_add(child_dentry, inode);

  kfree(name);
  return 0;
}

int networkfs_create(struct user_namespace *ns, struct inode *parent_inode,
                     struct dentry *child_dentry, umode_t mode, bool b) {
  return networkfs_generic_create(ns, parent_inode, child_dentry,
                                  mode | S_IFREG);
}

int networkfs_remove(struct inode *parent_inode, struct dentry *child_dentry,
                     const char *op) {
  char *name =
      encode_url_query(child_dentry->d_name.name, child_dentry->d_name.len);
  ino_t root = parent_inode->i_ino;

  char parent_inode_id[20];
  sprintf(parent_inode_id, "%ld", root);
  int rc =
      networkfs_http_call((const char *)parent_inode->i_sb->s_fs_info, op, NULL,
                          0, 2, "parent", parent_inode_id, "name", name);

  printk(KERN_INFO "%s: rc = %d\n", op, rc);
  if (rc < 0) {
    kfree(name);
    return rc;
  }

  kfree(name);
  return 0;
}

int networkfs_unlink(struct inode *parent_inode, struct dentry *child_dentry) {
  return networkfs_remove(parent_inode, child_dentry, "unlink");
}

int networkfs_mkdir(struct user_namespace *ns, struct inode *parent_inode,
                    struct dentry *child_dentry, umode_t mode) {
  return networkfs_generic_create(ns, parent_inode, child_dentry,
                                  mode | S_IFDIR);
}

int networkfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry) {
  return networkfs_remove(parent_inode, child_dentry, "rmdir");
}

struct inode_operations networkfs_inode_ops = {
    .lookup = networkfs_lookup,
    .create = networkfs_create,
    .unlink = networkfs_unlink,
    .mkdir = networkfs_mkdir,
    .rmdir = networkfs_rmdir,
};

int networkfs_iterate(struct file *filp, struct dir_context *ctx) {
  char *fsname;
  unsigned char ftype;
  ino_t dino;
  struct dentry *dentry = filp->f_path.dentry;
  struct inode *inode = dentry->d_inode;
  unsigned long offset = filp->f_pos;
  int stored = 0;
  ino_t ino = inode->i_ino;
  char inode_id[20];
  sprintf(inode_id, "%ld", ino);

  // Store at heap instead of stack to minimize stack frame
  struct networkfs_entries *response =
      kmalloc(sizeof(struct networkfs_entries), GFP_KERNEL);
  int rc = networkfs_http_call(
      dentry->d_sb->s_fs_info, "list", (void *)response,
      sizeof(struct networkfs_entries), 1, "inode", inode_id);
  printk(KERN_INFO "token: %s, rc: %d", (char *)dentry->d_sb->s_fs_info, rc);

  if (rc < 0) {
    printk(KERN_ERR "list request failed: %d\n", rc);
    kfree(response);
    return rc;
  }

  printk(KERN_INFO "success, so try to get count = %zu\n",
         response->entries_count);

  while (true) {
    if (offset == 0) {
      fsname = ".";
      ftype = DT_DIR;
      dino = ino;
    } else if (offset == 1) {
      fsname = "..";
      ftype = DT_DIR;
      dino = dentry->d_parent->d_inode->i_ino;
    } else if (offset < response->entries_count + 2) {
      fsname = response->entries[offset - 2].name;
      ftype = response->entries[offset - 2].entry_type;
      dino = response->entries[offset - 2].ino;
    } else {
      kfree(response);
      return stored;
    }
    printk(KERN_INFO "try emit: name = %s, type = %d\n", fsname, ftype);
    dir_emit(ctx, fsname, strlen(fsname), dino, ftype);
    stored++;
    offset++;
    ctx->pos = offset;
  }
  // Unreachable
  return stored;
}

struct file_operations networkfs_dir_ops = {
    .iterate = networkfs_iterate,
};

int networkfs_open(struct inode *node, struct file *filp) { return 0; }

ssize_t networkfs_read(struct file *filp, char *buffer, size_t len,
                       loff_t *offset) {
  ino_t ino = filp->f_inode->i_ino;
  void *response = kmalloc(1024, GFP_KERNEL);

  char inode_id[20];
  sprintf(inode_id, "%ld", ino);
  int rc = networkfs_http_call((const char *)filp->f_inode->i_sb->s_fs_info,
                               "read", response, 1024, 1, "inode", inode_id);

  if (rc < 0) {
    printk(KERN_ERR "read failed: %d\n", rc);
    kfree(response);
    return rc;
  }

  uint64_t content_len = *(uint64_t *)response;
  if (*offset == content_len) {
    return 0;
  }

  void *content = response + sizeof(uint64_t);
  if (*offset > content_len) {
    kfree(response);
    return -E2BIG;
  }

  uint64_t avaiable = min(content_len - *offset, len);
  rc = avaiable;
  if (copy_to_user(buffer, content + *offset, avaiable) != 0) {
    avaiable = 0;
    rc = -1;
  }

  *offset += avaiable;
  kfree(response);
  return rc;
}

ssize_t networkfs_write(struct file *filp, const char *buffer, size_t len,
                        loff_t *offset) {
  printk(KERN_INFO "enter write: len = %d, offset = %d\n", len, *offset);
  ino_t ino = filp->f_inode->i_ino;
  void *response = kmalloc(1024, GFP_KERNEL);

  char inode_id[20];
  sprintf(inode_id, "%ld", ino);
  int rc = networkfs_http_call((const char *)filp->f_inode->i_sb->s_fs_info,
                               "read", response, 1024, 1, "inode", inode_id);

  printk(KERN_INFO "copy file to local: rc = %d\n", rc);

  if (rc < 0) {
    printk(KERN_ERR "write failed: %d\n", rc);
    kfree(response);
    return rc;
  }

  uint64_t content_len = *(uint64_t *)response;
  void *content = response + sizeof(uint64_t);
  if (*offset > content_len) {
    printk(KERN_ERR "offset is to big\n");
    kfree(response);
    return -E2BIG;
  }

  if (copy_from_user(content + *offset, buffer, len) != 0) {
    printk("write copy_from_user failed\n");
    kfree(response);
    return -1;
  }

  content_len = *offset + len;
  *(char *)(content + content_len) = 0;
  char *encoded_content = encode_url_query(content, content_len);

  printk(KERN_INFO "len: %d, encoded_content: %s\n", strlen(encoded_content),
         encoded_content);

  rc = networkfs_http_call((const char *)filp->f_inode->i_sb->s_fs_info,
                           "write", NULL, 0, 2, "inode", inode_id, "content",
                           encoded_content);

  if (rc < 0) {
    printk(KERN_ERR "write failed: %d\n", rc);
    kfree(encoded_content);
    kfree(response);
    return rc;
  }

  *offset += len;
  kfree(encoded_content);
  kfree(response);
  return len;
}

int networkfs_release(struct inode *inode, struct file *filp) { return 0; }

struct file_operations networkfs_file_ops = {
    .open = networkfs_open,
    .read = networkfs_read,
    .write = networkfs_write,
    .release = networkfs_release,
};

int networkfs_fill_super(struct super_block *sb, void *data, int silent) {
  struct inode *inode;
  inode = networkfs_get_inode(sb, NULL, S_IFDIR | 0777, 1000);
  inode->i_op = &networkfs_inode_ops;
  inode->i_fop = &networkfs_dir_ops;
  sb->s_root = d_make_root(inode);
  if (sb->s_root == NULL) {
    return -ENOMEM;
  }
  printk(KERN_INFO "return 0\n");
  return 0;
}

struct dentry *networkfs_mount(struct file_system_type *fs_type, int flags,
                               const char *token, void *data) {
  struct dentry *ret;
  ret = mount_nodev(fs_type, flags, data, networkfs_fill_super);
  if (ret == NULL) {
    printk(KERN_ERR "Can't mount file system\n");
  } else {
    // CAUTION: possiable memory leak
    printk(KERN_INFO "token: %s", token);
    ret->d_sb->s_fs_info = kstrdup(token, GFP_KERNEL);
    printk(KERN_INFO "Mounted successfuly\n");
  }
  return ret;
}

void networkfs_kill_sb(struct super_block *sb) {
  kfree(sb->s_fs_info);
  printk(KERN_INFO
         "networkfs super block is destroyed. Unmount successfully.\n");
}

struct file_system_type networkfs_fs_type = {
    .name = "networkfs",
    .mount = networkfs_mount,
    .kill_sb = networkfs_kill_sb,
};

int networkfs_init(void) {
  printk(KERN_INFO "Insert networkfs module\n");
  return register_filesystem(&networkfs_fs_type);
}

void networkfs_exit(void) {
  unregister_filesystem(&networkfs_fs_type);
  printk(KERN_INFO "Delete networkfs module!\n");
}

module_init(networkfs_init);
module_exit(networkfs_exit);
