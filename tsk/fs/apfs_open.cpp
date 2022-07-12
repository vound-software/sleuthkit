/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2019-2020 Brian Carrier.  All Rights reserved
 * Copyright (c) 2018-2019 BlackBag Technologies.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "../libtsk.h"

#include "apfs_compat.hpp"
#include "../img/pool.hpp"
#include "../pool/apfs_pool_compat.hpp"
#include "tsk_fs_i.h"

TSK_FS_INFO* apfs_open_auto_detect(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM fstype, uint8_t test) {

    return apfs_open(img_info, offset, fstype, "");
}

TSK_FS_INFO* apfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
                       TSK_FS_TYPE_ENUM fstype, const char* pass) {
  tsk_error_reset();

  if (img_info->itype != TSK_IMG_TYPE_POOL) {
      tsk_error_reset();
      tsk_error_set_errno(TSK_ERR_FS_ARG);
      tsk_error_set_errstr("tsk_apfs_open: Not a pool image");
      return nullptr;
  }
  IMG_POOL_INFO *pool_img = (IMG_POOL_INFO*)img_info; 

  if (pool_img->pool_info == nullptr) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_open: Null pool_info");
    return nullptr;
  }

  if (fstype != TSK_FS_TYPE_APFS) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_ARG);
    tsk_error_set_errstr("tsk_apfs_open: invalid fstype");
    return nullptr;
  }

  try {
    auto fs = new APFSFSCompat(img_info, pool_img->pool_info, pool_img->pvol_block, pass);
    return &fs->fs_info();
  } catch (std::runtime_error& e) {
    tsk_error_set_errno(TSK_ERR_FS_GENFS);
    tsk_error_set_errstr("tsk_apfs_open: %s", e.what());
    return nullptr;
  }
}


TSK_FS_INFO* tsk_vound_open_pool_decrypt_internal(TSK_IMG_INFO* img, TSK_POOL_INFO* pool_info, long offset, TSK_FS_TYPE_ENUM fstype, char* password) {

    TSK_POOL_VOLUME_INFO* pvol_info = pool_info->vol_list;
    TSK_IMG_INFO* pimg_info = pool_info->get_img_info(pool_info, pvol_info->block);

    return tsk_fs_open_img_decrypt(pimg_info, pvol_info->block, TSK_FS_TYPE_APFS, password);
}


TSK_FS_INFO* tsk_vound_open_pool(TSK_IMG_INFO* img, TSK_POOL_INFO* pool_info, long offset, TSK_FS_TYPE_ENUM fstype) {

    return tsk_vound_open_pool_decrypt_internal(img, pool_info, offset, fstype, "");
}


