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

struct inode_operations networkfs_inode_ops;
struct file_operations networkfs_dir_ops;

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
  }
  return inode;
}

struct dentry *networkfs_lookup(struct inode *parent_inode,
                                struct dentry *child_dentry,
                                unsigned int flag) {
  printk(KERN_INFO "lookup to %s\n", child_dentry->d_name.name);
  ino_t root;
  struct inode *inode;
  const char *name = child_dentry->d_name.name;
  root = parent_inode->i_ino;
  char inode_id[16];
  sprintf(inode_id, "%ld", root);
  struct networkfs_entries *response =
      kmalloc(sizeof(struct networkfs_entries), GFP_KERNEL);
  int rc = networkfs_http_call(
      parent_inode->i_sb->s_fs_info, "list", (void *)response,
      sizeof(struct networkfs_entries), 1, "inode", inode_id);
  printk(KERN_INFO "rc: %d", rc);

  if (rc == 0) {
    printk(KERN_INFO "success, so try to get count = %zu\n",
           response->entries_count);
  } else {
    kfree(response);
    return NULL;
  }

  for (size_t i = 0; i < response->entries_count; i++) {
    if (!strcmp(name, response->entries[i].name)) {
      mode_t type =
          response->entries[i].entry_type == DT_DIR ? S_IFDIR : S_IFREG;
      inode = networkfs_get_inode(parent_inode->i_sb, NULL, type | 0777,
                                  response->entries[i].ino);
      d_add(child_dentry, inode);
    }
  }

  kfree(response);
  return NULL;
}

int networkfs_create(struct user_namespace *ns, struct inode *parent_inode,
                     struct dentry *child_dentry, umode_t mode, bool b) {
  ino_t root;
  struct inode *inode;
  const char *name = child_dentry->d_name.name;
  root = parent_inode->i_ino;

  // TODO: error handling
  ino_t new_inode;
  const char *type = mode & S_IFREG ? "file" : "directory";
  char parent_inode_id[10];
  sprintf(parent_inode_id, "%ld", root);
  int rc = networkfs_http_call(
      (const char *)parent_inode->i_sb->s_fs_info, "create", (void *)&new_inode,
      sizeof(ino_t), 3, "parent", parent_inode_id, "name", name, "type", type);

  printk(KERN_INFO "create: rc = %d\n", rc);

  if (rc != 0) {
    return 0;
  }

  inode =
      networkfs_get_inode(parent_inode->i_sb, NULL, S_IFREG | 0777, new_inode);
  d_add(child_dentry, inode);

  return 0;
}

int networkfs_unlink(struct inode *parent_inode, struct dentry *child_dentry) {
  const char *name = child_dentry->d_name.name;
  ino_t root = parent_inode->i_ino;

  char parent_inode_id[10];
  sprintf(parent_inode_id, "%ld", root);
  int rc =
      networkfs_http_call((const char *)parent_inode->i_sb->s_fs_info, "unlink",
                          NULL, 0, 2, "parent", parent_inode_id, "name", name);

  printk(KERN_INFO "unlink: rc = %d\n", rc);
  return 0;
}

int networkfs_mkdir(struct user_namespace *ns, struct inode *parent_inode,
                    struct dentry *child_dentry, umode_t mode) {
  struct inode *inode;
  ino_t root = parent_inode->i_ino;
  const char *name = child_dentry->d_name.name;

  // TODO: error handling
  ino_t new_inode;
  char parent_inode_id[10];
  sprintf(parent_inode_id, "%ld", root);
  int rc =
      networkfs_http_call((const char *)parent_inode->i_sb->s_fs_info, "create",
                          (void *)&new_inode, sizeof(ino_t), 3, "parent",
                          parent_inode_id, "name", name, "type", "directory");

  printk(KERN_INFO "mkdir: rc = %d\n", rc);

  if (rc != 0) {
    return 0;
  }

  inode = networkfs_get_inode(parent_inode->i_sb, parent_inode, S_IFDIR | 0777,
                              new_inode);
  d_add(child_dentry, inode);

  return 0;
}

int networkfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry) {
  const char *name = child_dentry->d_name.name;
  ino_t root = parent_inode->i_ino;

  char parent_inode_id[10];
  sprintf(parent_inode_id, "%ld", root);
  int rc =
      networkfs_http_call((const char *)parent_inode->i_sb->s_fs_info, "rmdir",
                          NULL, 0, 2, "parent", parent_inode_id, "name", name);

  printk(KERN_INFO "rmdir: rc = %d\n", rc);
  return 0;
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
  struct dentry *dentry;
  struct inode *inode;
  unsigned long offset;
  int stored;
  unsigned char ftype;
  ino_t ino;
  ino_t dino;
  dentry = filp->f_path.dentry;
  inode = dentry->d_inode;
  offset = filp->f_pos;
  stored = 0;
  ino = inode->i_ino;
  char inode_id[10];
  sprintf(inode_id, "%ld", ino);

  // Store at heap instead of stack to minimize stack frame
  struct networkfs_entries *response =
      kmalloc(sizeof(struct networkfs_entries), GFP_KERNEL);
  int rc = networkfs_http_call(
      dentry->d_sb->s_fs_info, "list", (void *)response,
      sizeof(struct networkfs_entries), 1, "inode", inode_id);
  printk(KERN_INFO "token: %s, rc: %d", (char *)dentry->d_sb->s_fs_info, rc);

  if (rc == 0) {
    printk(KERN_INFO "success, so try to get count = %zu\n",
           response->entries_count);
  } else {
    kfree(response);
    return 0;
  }

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
  return stored;
}

struct file_operations networkfs_dir_ops = {
    .iterate = networkfs_iterate,
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
