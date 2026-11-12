/*
 * Thin JNI shim: TProxyStartServiceFromStr → hev_socks5_tunnel_main_from_str
 * (exported by libhev-socks5-tunnel.so but not registered by upstream sockstun JNI).
 *
 * Build: ./native/hev-fromstr/build.sh
 */
#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "hev_fromstr_jni"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

typedef int (*hev_main_from_str_t)(const char *config_str, int config_len, int tun_fd);

struct from_str_args {
    char *config;
    int config_len;
    int tun_fd;
    hev_main_from_str_t main_fn;
};

static void *from_str_thread(void *arg) {
    struct from_str_args *a = (struct from_str_args *)arg;
    int rc = a->main_fn(a->config, a->config_len, a->tun_fd);
    ALOGI("hev_socks5_tunnel_main_from_str exited rc=%d", rc);
    free(a->config);
    free(a);
    return NULL;
}

static jint
TProxyStartServiceFromStr(JNIEnv *env, jclass clazz, jstring config, jint fd) {
    (void)clazz;
    if (config == NULL || fd < 0) {
        ALOGE("FromStr: bad args");
        return -1;
    }
    void *hev = dlopen("libhev-socks5-tunnel.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hev) {
        hev = dlopen("libhev-socks5-tunnel.so", RTLD_NOW);
    }
    if (!hev) {
        ALOGE("dlopen hev failed: %s", dlerror());
        return -2;
    }
    hev_main_from_str_t main_fn =
        (hev_main_from_str_t)dlsym(hev, "hev_socks5_tunnel_main_from_str");
    if (!main_fn) {
        ALOGE("dlsym main_from_str failed: %s", dlerror());
        return -3;
    }
    const char *utf = (*env)->GetStringUTFChars(env, config, NULL);
    if (!utf) return -4;
    jsize len = (*env)->GetStringUTFLength(env, config);
    char *copy = (char *)malloc((size_t)len + 1);
    if (!copy) {
        (*env)->ReleaseStringUTFChars(env, config, utf);
        return -5;
    }
    memcpy(copy, utf, (size_t)len);
    copy[len] = '\0';
    (*env)->ReleaseStringUTFChars(env, config, utf);

    struct from_str_args *args = (struct from_str_args *)malloc(sizeof(*args));
    if (!args) {
        free(copy);
        return -5;
    }
    args->config = copy;
    args->config_len = (int)len;
    args->tun_fd = fd;
    args->main_fn = main_fn;

    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int prc = pthread_create(&thr, &attr, from_str_thread, args);
    pthread_attr_destroy(&attr);
    if (prc != 0) {
        ALOGE("pthread_create failed %d", prc);
        free(copy);
        free(args);
        return -6;
    }
    return 0;
}

static JNINativeMethod gMethods[] = {
    {"TProxyStartServiceFromStr", "(Ljava/lang/String;I)I",
     (void *)TProxyStartServiceFromStr},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = (*env)->FindClass(env, "hev/sockstun/TProxyService");
    if (!cls) {
        ALOGE("FindClass TProxyService failed");
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, cls, gMethods,
                                (jint)(sizeof(gMethods) / sizeof(gMethods[0]))) != 0) {
        ALOGE("RegisterNatives failed");
        return JNI_ERR;
    }
    ALOGI("hev_fromstr_jni registered TProxyStartServiceFromStr");
    return JNI_VERSION_1_6;
}
