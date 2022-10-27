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

TSK_POOL_VOLUME_INFO* get_pool_volume_info_by_block(IMG_POOL_INFO* pool_info, long blockNum);

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

    TSK_POOL_VOLUME_INFO* img_ref = get_pool_volume_info_by_block(pool_img, offset);
    auto fs = new APFSFSCompat(img_info, pool_img->pool_info, img_ref->block, pass);
    
    return &fs->fs_info();

  } catch (std::runtime_error& e) {
    tsk_error_set_errno(TSK_ERR_FS_GENFS);
    tsk_error_set_errstr("tsk_apfs_open: %s", e.what());
    return nullptr;
  }

}

TSK_POOL_VOLUME_INFO* get_pool_volume_info_by_block(IMG_POOL_INFO* pool_info, long blockNum) {
    
    TSK_POOL_VOLUME_INFO* result = pool_info->pool_info->vol_list;
    
    do {
        if (result->block == blockNum) {
            return result;
        }
        result = result->next;

    } while (result != NULL);
    
    return NULL;

}

TSK_FS_INFO* tsk_vound_open_pool_decrypt_internal(TSK_IMG_INFO* img, TSK_POOL_INFO* pool_info, long offset, int fsNum, TSK_FS_TYPE_ENUM fstype, char* password) {

    TSK_POOL_VOLUME_INFO* tmp_pvol_info = pool_info->vol_list;
    TSK_POOL_VOLUME_INFO* pvol_info = pool_info->vol_list;
    int counter = fsNum;
    
    while (counter > 0) {
        
        if (tmp_pvol_info->next == NULL) {
            return NULL;
        }
        tmp_pvol_info = tmp_pvol_info->next;
        pvol_info = tmp_pvol_info;
        counter--;

    }

    TSK_IMG_INFO* pimg_info = pool_info->get_img_info(pool_info, pvol_info->block);

    return tsk_fs_open_img_decrypt(pimg_info, pvol_info->block, TSK_FS_TYPE_APFS, password);
}

TSK_FS_INFO* tsk_vound_open_pool(TSK_IMG_INFO* img, TSK_POOL_INFO* pool_info, long offset, int fsNum,  TSK_FS_TYPE_ENUM fstype) {

    if (pool_info->num_vols <= fsNum ) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_POOL_MAX);
        tsk_error_set_errstr("tsk_vound_open_pool: requested fsNum exceede max available poool fs");
        return nullptr;
    }

    return tsk_vound_open_pool_decrypt_internal(img, pool_info, offset, fsNum, fstype, "");
}
