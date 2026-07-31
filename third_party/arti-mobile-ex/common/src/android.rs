#![allow(non_snake_case)]

use crate::{
    apply_arti_max_dirtiness, arti_bootstrap_fraction, arti_ready_for_traffic, set_arti_dormant,
    start_arti_proxy, stop_arti_proxy, ONIONVPN_CONTROL_API_VERSION,
};
use std::sync::Arc;

use jni::objects::{AutoLocal, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jfloat, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{Executor, JNIEnv};

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiJNI_stopArtiProxyJNI<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    stop_arti_proxy();
}

/// Create a static method myMethod on class net.example.MyClass
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiJNI_startArtiProxyJNI<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    cacheDir: JString<'local>,
    stateDir: JString<'local>,
    obfs4Port: jint,
    snowflakePort: jint,
    obfs4proxyPath: JString<'local>,
    bridgeLines: JString<'local>,
    socks_port: jint,
    dns_port: jint,
    loggingCallback: JObject<'local>,
) -> jstring {
    let cacheDir: String = env
        .get_string(&cacheDir)
        .expect("cache_dir is invalid")
        .to_string_lossy()
        .into_owned();
    let stateDir: String = env
        .get_string(&stateDir)
        .expect("state_dir is invalid")
        .to_string_lossy()
        .into_owned();
    let obfs4proxyPath: Option<String> = match env.get_string(&obfs4proxyPath) {
        Ok(v) => Some(v.to_string_lossy().into_owned()),
        Err(_) => None,
    };
    let bridgeLines: Option<String> = match env.get_string(&bridgeLines) {
        Ok(v) => Some(v.to_string_lossy().into_owned()),
        Err(_) => None,
    };

    let log_cb_ref = env
        .new_global_ref(loggingCallback)
        .expect("couldn't create global ref to log callback");
    let exec = Executor::new(Arc::new(
        env.get_java_vm().expect("could get jvm ref from env"),
    ));

    let result = match start_arti_proxy(
        &cacheDir,
        &stateDir,
        obfs4Port as u16,
        snowflakePort as u16,
        obfs4proxyPath.as_deref(),
        bridgeLines.as_deref(),
        socks_port as u16,
        dns_port as u16,
        move |buf: &[u8]| {
            let msg =
                std::str::from_utf8(buf).expect("couldn't convert buffered log message to str");
            exec.with_attached(|env| -> Result<(), jni::errors::Error> {
                let jmsg: AutoLocal<JObject> = env.auto_local(
                    env.new_string(msg)
                        .expect("couldn't convert log message to jstring")
                        .into(),
                );
                env.call_method(
                    &log_cb_ref,
                    "log",
                    "(Ljava/lang/String;)V",
                    &[JValue::from(&jmsg)],
                )
                .expect("calling log callback method failed");
                Ok(())
            })
            .expect("attaching to Executor failed: log callback");
        },
    ) {
        Ok(res) => format!("Output: {}", res),
        Err(e) => format!("Error: {}", e),
    };

    env.new_string(result)
        .expect("Couldn't create Java string!")
        .into_raw()
}

// --- OnionVPN Ext control API (ArtiControlNative) ---

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiControlNative_controlApiVersionJNI<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jint {
    ONIONVPN_CONTROL_API_VERSION
}

/// soft=true → DormantMode::Soft; soft=false → DormantMode::Normal (ACTIVE).
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiControlNative_setDormantJNI<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    soft: jboolean,
) -> jboolean {
    match set_arti_dormant(soft != JNI_FALSE) {
        Ok(()) => JNI_TRUE,
        Err(e) => {
            tracing::warn!("setDormantJNI failed: {e}");
            JNI_FALSE
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiControlNative_applyMaxDirtinessJNI<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    seconds: jint,
) -> jboolean {
    let secs = if seconds < 60 {
        60u64
    } else {
        seconds as u64
    };
    match apply_arti_max_dirtiness(secs) {
        Ok(()) => JNI_TRUE,
        Err(e) => {
            tracing::warn!("applyMaxDirtinessJNI failed: {e}");
            JNI_FALSE
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiControlNative_bootstrapFractionJNI<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jfloat {
    arti_bootstrap_fraction()
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_torproject_arti_ArtiControlNative_readyForTrafficJNI<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    if arti_ready_for_traffic() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
