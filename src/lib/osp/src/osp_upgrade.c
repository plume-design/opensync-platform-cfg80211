/*
Copyright (c) 2020, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <sys/types.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <ev.h>
#include "target.h"
#include "osp.h"

#define TEMP_PATH "/tmp/pfirmware/"
#define IMG_MAX_SIZE 40 //MB

struct osp_dl_data
{
    osp_upg_cb callback;
    uint32_t dl_timeout;
};

struct osp_upg_data
{
    osp_upg_cb callback;
    char *upg_password;
};

static osp_upg_status_t status;

static ev_timer  osp_dtimer;
static ev_timer  osp_utimer;

static bool upg_running = false;
static char upg_url[256];
static char file_path_md5[256];
static char upg_url_md5[256];

static void osp_upg_get_img_path(char *buf, int buflen)
{
    char *file_name;
    file_name = basename(upg_url);
    snprintf(buf, buflen, TEMP_PATH "%s", file_name);
}

static bool osp_upg_dev_space_check()
{
    FILE *fp = NULL;
    char buf[128];

    status = OSP_UPG_OK;
    fp = popen("df /tmp/ | grep tmpfs | awk '{print $4}'", "r");
    if (fp == NULL)
    {
        LOG(ERR, "UM: popen call failed");
        status = OSP_UPG_INTERNAL;
        return false;
    }

    if (!fgets(buf, sizeof(buf), fp))
    {
        LOG(ERR, "UM: fgets call failed");
        status = OSP_UPG_INTERNAL;
        pclose(fp);
        return false;
    }
    pclose(fp);

    // df returns kB, IMG_MAX_SIZE is in MB
    if ((int)(atoll(buf) / 1024) < IMG_MAX_SIZE)
    {
        LOG(ERR, "UM: Device is running out of space");
        status = OSP_UPG_DL_NOFREE;
        return false;
    }
    return true;
}

static size_t osp_upg_fetch_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    return fwrite(ptr, size, nmemb, stream);
}

static void osp_upg_curl_free(CURL *curl)
{
    if (curl == NULL) return;

    curl_easy_cleanup(curl);
}

static bool osp_upg_download_image(int timeout, long file_size)
{
    CURL *curl;
    CURLcode curl_ret;
    CURLcode curl_ret_md5;
    FILE *fp = NULL;
    FILE *fp_md5 = NULL;
    char file_path[128];

    status = OSP_UPG_OK;
    curl = curl_easy_init();

    if (curl == NULL)
    {
        status = OSP_UPG_INTERNAL;
        LOG(ERR, "UM: curl_easy_init failed");
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout);
    curl_easy_setopt(curl, CURLOPT_URL, upg_url);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, osp_upg_fetch_data);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM, file_size);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);

    osp_upg_get_img_path(file_path, sizeof(file_path));

    fp = fopen(file_path, "wb");

    if (fp == NULL)
    {
        status = OSP_UPG_INTERNAL;
        LOG(ERR, "UM: fopen failed");
        osp_upg_curl_free(curl);
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    curl_ret = curl_easy_perform(curl);
    fclose(fp);

    if (curl_ret != CURLE_OK)
    {
        status = OSP_UPG_DL_FW;
        LOG(ERR, "UM: Failed to download (CURLError: %s)", curl_easy_strerror(curl_ret));
        osp_upg_curl_free(curl);
        remove(file_path);
        return false;
    }

    strcpy(upg_url_md5, upg_url);
    strcpy(file_path_md5, file_path);
    strcat(upg_url_md5, ".md5");
    strcat(file_path_md5, ".md5");
    curl_easy_setopt(curl, CURLOPT_URL, upg_url_md5);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, osp_upg_fetch_data);

    fp_md5 = fopen(file_path_md5, "wb");
    if (fp_md5 == NULL)
    {
        status = OSP_UPG_INTERNAL;
        LOG(ERR, "UM: fopen failed");
        osp_upg_curl_free(curl);
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp_md5);

    curl_ret_md5 = curl_easy_perform(curl);
    fclose(fp_md5);

    if (curl_ret_md5 != CURLE_OK)
    {
        status = OSP_UPG_DL_MD5;
        memset(upg_url_md5, 0, sizeof(upg_url_md5));
        LOG(ERR, "UM: Failed to download (CURLError: %s)", curl_easy_strerror(curl_ret_md5));
        osp_upg_curl_free(curl);
        remove(file_path_md5);
        return false;
    }

    osp_upg_curl_free(curl);

    return true;
}

static bool osp_upg_download_url(int timeout)
{
    char file_path[128];
    char *file_name;
    status = OSP_UPG_OK;
    unsigned long file_size;
    struct stat st_buf;
    struct stat st = {0};

    if (stat("/tmp/pfirmware", &st) == -1)
    {
        mkdir("/tmp/pfirmware", 0777);
    }

    file_name = basename(upg_url);
    LOGI("UM: Downloading image: (%s), from url: %s", file_name, upg_url);

    osp_upg_get_img_path(file_path, sizeof(file_path));

    if (stat(file_path, &st_buf) != 0)
    {
        file_size = 0;
    }
    else
    {
        file_size = st_buf.st_size;
    }

    return osp_upg_download_image(timeout, file_size);
}

char* upg_img_basename(char *url)
{
    char *basename = NULL;

    /* find the last / in url */
    basename = strrchr(url, '/');

    /* check if / found and if / is on string end
     * like: http:// http://192.168.4.15/ etc
     */
    if ((NULL != basename) && (*(basename + 1) != '\0'))
    {
        /* advanced to first name char */
        basename++;

        /* verify filename size */
        if (strlen(basename) == 0)
        {
            /* size not right, LOG, and run away */
            LOG(ERR, "Filename len is 0 !!!");
            basename = NULL;
        }
    }
    else
    {
        LOG(ERR, "No / found in URL - %s not a valid URL", url);
    }

    return basename;
}

bool upg_img_checkmd5(char *upg_url, char *upg_dir)
{
    int ret = 0;
    char buff[1024];
    char *fname;
    char md5_url[256];
    struct stat st_buf_md5;

    /* get the file name out of URL */
    fname = upg_img_basename(upg_url);
    if (NULL == fname)
    {
       return false;
    }

    /* set both url and url of md5 checksum */
    if ((0 <= sprintf(md5_url, "%s", upg_url)))
    {
        LOG(DEBUG, "Setting md5 URL to %s", md5_url);

    }

    /* verify that md5 image size is not 0
     * This is because md5 verification goes well in case md5 file is zero
     */
    snprintf(buff, sizeof(buff), "%s/%s", upg_dir, fname);
    if (stat(buff, &st_buf_md5) != 0)
    {
        LOG(ERR, "File %s doesn't exist", md5_url);
        LOG(ERR, "md5 file is either missing or empty");
        status = OSP_UPG_DL_MD5;
        return false;
    }

    if (st_buf_md5.st_size < 0)
    {
        LOG(ERR, "File %s is empty", md5_url);
        status = OSP_UPG_DL_MD5;
        return false;
    }

    memset(buff, 0, sizeof(buff));
    memset(md5_url, 0, sizeof(md5_url));
    sprintf(md5_url, "%s.md5", fname);

    /* prepare command */
    snprintf(buff, sizeof(buff), "(cd %s && md5sum -c %s) > /dev/null 2>&1", upg_dir, md5_url);

    /* execute command */
    ret = system(buff);

    /* check command status */
    ret = WEXITSTATUS(ret);

    if (ret != 0)
    {
        LOG(ERR, "MD5 sum verification failed: %d", ret);
        status = OSP_UPG_MD5_FAIL;
        return false;
    }
    else
    {
        return true;
    }

}

static void cb_osp_start_download(EV_P_ ev_timer *w, int events)
{
    struct osp_dl_data *dl_data = w->data;
    int ret;
    status = OSP_UPG_OK;

    // stop timer watcher
    ev_timer_stop(EV_A_ w);

    LOGI("UM: Timeout from struct %d", dl_data->dl_timeout);

    if (!osp_upg_download_url(dl_data->dl_timeout))
    {
        LOG(ERR, "UM: Error downloading %s", upg_url);
        status = status;

        // clear library URL if download failed allow repeating same URL in case of failure
        upg_url[0]=0;
        upg_url_md5[0]=0;
    }

    if (dl_data->callback == NULL)
    {
        LOGE("UM: (%s) Download Callback is NULL", __func__);
        goto cleanup;
    }

    dl_data->callback(OSP_UPG_DL, status, 100);

    ret = upg_img_checkmd5(upg_url_md5, TEMP_PATH);

    if (ret == false)
    {
        LOG(ERR, "UM: MD5 check sum failed");
        upg_url_md5[0]=0;
        dl_data->callback(OSP_UPG_DL, OSP_UPG_MD5_FAIL, 100);
    }

cleanup:
    free(w->data);
}

static bool upg_upgrade(const char *password)
{
    char img_path[128];
    struct stat st_buf;
    char cmd[128];
    int ret_status;

    osp_upg_get_img_path(img_path, sizeof(img_path));

    if (stat(img_path, &st_buf) != 0)
    {
        LOG(ERR, "UM: File %s doesn't exist", img_path);
        status = OSP_UPG_IMG_FAIL;
        return false;
    }

    if (st_buf.st_size < 0)
    {
        LOG(ERR, "UM: File %s is empty", img_path);
        status = OSP_UPG_IMG_FAIL;
        return false;
    }

    LOGI("UM: Upgrading the image...");
    snprintf(cmd, sizeof(cmd), "sysupgrade -n -v %s", img_path);

    LOGI("UM: Upgraded with image %s", img_path);
    ret_status = system(cmd);

    if (!WIFEXITED(ret_status) || WEXITSTATUS(ret_status) != 0)
    {
        LOGI("UM: sysupgrade failed");
        status = OSP_UPG_FL_WRITE;
        return false;
    }

    return true;
}

static void cb_osp_start_upgrade(EV_P_ ev_timer *w, int events)
{
    struct osp_upg_data *upg_data = w->data;
    status = OSP_UPG_OK;

    // stop timer watcher
    ev_timer_stop(EV_A_ w);

    if (upg_data == NULL) return;

    upg_running = true;

    if (!upg_upgrade(upg_data->upg_password))
    {
        LOG(ERR, "UM: Error upgrading device, URL: %s", upg_url);
        status = status;
    }

    upg_running = false;

    if (upg_data->callback == NULL)
    {
        LOGE("UM: (%s) Upgrade Callback is NULL", __func__);
        goto cleanup;
    }

    upg_data->callback(OSP_UPG_UPG, status, 100);

cleanup:
    free(w->data);
}

static bool osp_upg_set_url(const char *url)
{
    status = OSP_UPG_OK;

    // Make sure url is not empty
    if (url[0] == 0)
    {
        status = OSP_UPG_ARGS;
        LOG(ERR, "UM: URL must not be empty");
        return false;
    }

    // Copying the url to upg_url
    if (STRSCPY(upg_url, url) < 0)
    {
        status = OSP_UPG_ARGS;
        LOG(ERR, "UM: URL too long / buffer too small");
        return false;
    }

    LOGI("UM: Copied %s to upg_url", url);

    return true;
}

/*
 * FW Upgrade API
 */
/**
 * @brief Check system requirements for upgrade, like
 *        no upgrade in progress, available flash space etc
 */
bool osp_upg_check_system(void)
{
    status = OSP_UPG_OK;

    if (!osp_upg_dev_space_check())
    {
        return false;
    }

    if (upg_running)
    {
        status = OSP_UPG_SU_RUN;
        return false;
    }

    return true;
}

/**
 * Download an image suitable for upgrade from @p uri store it locally.
 * Upon download and verification completion, invoke the @p dl_cb callback.
 */
bool osp_upg_dl(char *url, uint32_t timeout, osp_upg_cb dl_cb)
{
    struct osp_dl_data *dl_data;

    status = OSP_UPG_OK;

    if (!osp_upg_set_url(url))
    {
        LOG(ERR, "UM: Error setting URL");
        status = status;
        return false;
    }

    dl_data = malloc(sizeof(struct osp_dl_data));
    if (dl_data == NULL)
    {
        LOG(ERR, "UM: Unable to allocate the download struct - malloc failed");
        status = OSP_UPG_INTERNAL;
        return false;
    }

    dl_data->callback = dl_cb;
    dl_data->dl_timeout = timeout;

    ev_timer_init(&osp_dtimer, cb_osp_start_download, 0, 0);
    osp_dtimer.data = dl_data;
    ev_timer_start(EV_DEFAULT , &osp_dtimer);

    return true;
}

/**
 * Write the previously downloaded image to the system. If the image
 * is encrypted, a password must be specified in @password.
 *
 * After the image was successfully applied, the @p upg_cb callback is invoked.
 */
bool osp_upg_upgrade(char *password, osp_upg_cb upg_cb)
{
    struct osp_upg_data *upg_data;

    status = OSP_UPG_OK;
    upg_data = malloc(sizeof(struct osp_upg_data));
    if (upg_data == NULL)
    {
        LOG(ERR, "UM: Unable to allocate the upgrade struct - malloc failed");
        status = OSP_UPG_INTERNAL;
        return false;
    }

    upg_data->callback = upg_cb;
    upg_data->upg_password = NULL;
    if (password)
    {
        upg_data->upg_password = strdup(password);
    }

    ev_timer_init(&osp_utimer, cb_osp_start_upgrade, 0, 0);
    osp_utimer.data = upg_data;
    ev_timer_start(EV_DEFAULT , &osp_utimer);

    return true;
}

/**
 * On dual-boot system, flag the newly flashed image as the active one.
 * This can be a no-op on single image systems.
 */
bool osp_upg_commit(void)
{
    /*
     * Current implementation of libupgrade sets bootconfig commit together
     * with upg_upgrade call so no action is needed at this point.
     */
    return true;
}

/**
 * Return more detailed error code in relation to a failed osp_upg_() function.
 * See osp_upg_status_t for a detailed list of error codes.
 */
int osp_upg_errno(void)
{
    return status;
}
