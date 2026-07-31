current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
rust-installed-targets := $(shell rustup target list --installed)
ANDROID_TARGETS := \
	armv7-linux-androideabi \
	aarch64-linux-android \
	x86_64-linux-android
IOS_TARGETS := \
	aarch64-apple-ios \
	aarch64-apple-ios-sim \
	x86_64-apple-ios
MACOS_TARGETS := \
	aarch64-apple-darwin \
	x86_64-apple-darwin
FILENAME := libarti_mobile.a

export NDK_HOME=${current_dir}cache/ndk/android-ndk-r28c
export ANDROID_NDK_HOME=${NDK_HOME}

all: release
release: android ios macos
debug: android-debug ios-debug macos-debug

android: android-release

android-debug: android-install-deps
	cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 -o ../android/arti/src/main/jniLibs build

android-debug-x86_64: android-install-deps
	cargo ndk -t x86_64 -o ../android/arti/src/main/jniLibs build

android-release: android-install-deps
	RUSTFLAGS='-C link-arg=-s' cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 -o ../android/arti/src/main/jniLibs build --release

android-release-arm64: android-install-deps
	RUSTFLAGS='-C link-arg=-s' cargo ndk -t arm64-v8a -o ../android/arti/src/main/jniLibs build --release

android-release-x86_64: android-install-deps
	RUSTFLAGS='-C link-arg=-s' cargo ndk -t x86_64 -o ../android/arti/src/main/jniLibs build --release

org_torproject_arti_ArtiJNI.h:
	javac \
		-h . \
		-classpath ../android/arti/src/main/java/ \
		../android/arti/src/main/java/org/torproject/arti/ArtiJNI.java
	find ../android/arti/src/main/java -name "*.class" | xargs rm

ios: ios-release

ios-debug: export IPHONEOS_DEPLOYMENT_TARGET=15.0
ios-debug: lipo-ios-debug ios-debug-aarch64-apple-ios

ios-release: export IPHONEOS_DEPLOYMENT_TARGET=15.0
ios-release: ios-release-aarch64-apple-ios #Simulator is never released, so don't build these targets.

macos: macos-release

macos-debug: export MACOSX_DEPLOYMENT_TARGET=11.0
macos-debug: lipo-macos-debug

macos-release: export MACOSX_DEPLOYMENT_TARGET=11.0
macos-release: lipo-macos-release

arti-mobile.h:
	cbindgen src/apple.rs -l c > arti-mobile.h

# Args:
# $1: OS name
# $2: Rust target name
# $3: Release mode
define apple-build-rules

$(1)-$(3)-$(2): $(1)-install-deps arti-mobile.h
ifeq ($(3), release)
	cargo build --target $(2) --release
else
	cargo build --target $(2)
endif

.PHONY: $(1)-$(3)-$(2)
endef

$(foreach target, $(IOS_TARGETS), $(eval $(call apple-build-rules,ios,$(target),debug)))
$(foreach target, $(IOS_TARGETS), $(eval $(call apple-build-rules,ios,$(target),release)))
$(foreach target, $(MACOS_TARGETS), $(eval $(call apple-build-rules,macos,$(target),debug)))
$(foreach target, $(MACOS_TARGETS), $(eval $(call apple-build-rules,macos,$(target),release)))

clean:
	cargo clean
	cargo uninstall cargo-ndk  # make sure we have a intuitive way to recover from broken builds due to oudated cargo-ndk
	rm -rf arti-mobile.h org_torproject_arti_ArtiJNI.h jniLibs ../android/arti/src/main/jniLibs

clean-all: clean
	rm -rf cache

android-install-deps: cache/ndk/android-ndk-r28c cargo-ndk android-targets

ios-install-deps: ios-targets cbindgen

macos-install-deps: macos-targets cbindgen

cache/ndk/android-ndk-r28c: cache/ndk.zip
	unzip -n -d cache/ndk cache/ndk.zip
	touch cache/ndk.zip #MacOS' unzip might delete the zip file, so recreate an empty file to calm make.

# rustc looks for the compiler-rt builtins under lib/clang/17, but NDK r28c
# ships clang 19; bridge the version dir so -lclang_rt.builtins-* resolves.
ifeq ($(shell uname), Darwin)
	ln -sFf darwin-x86_64 ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64
	ln -sFf 19 ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/lib/clang/17
else
	ln -sfn 19 ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/17
endif

cache/ndk.zip:
	mkdir -p cache

ifeq ($(OS),Windows_NT)
	wget https://dl.google.com/android/repository/android-ndk-r28c-windows.zip -O $@
else ifeq ($(shell uname), Linux)
	wget https://dl.google.com/android/repository/android-ndk-r28c-linux.zip -O $@
else ifeq ($(shell uname), Darwin)
	wget https://dl.google.com/android/repository/android-ndk-r28c-darwin.zip -O $@
else
	@echo "No NDK found for your system, please download it by yourself."
	@false
endif

cargo-ndk:
ifeq ($(shell command -v cargo-ndk),)
	cargo install cargo-ndk
endif

cbindgen:
ifeq ($(shell command -v cbindgen),)
	cargo install cbindgen
endif

# Args:
# $1: Rust target name
# $2: OS name
define target-rules

$(2)-target-$(1):
ifeq ($$(filter $(1), $$(rust-installed-targets)),)
	rustup target install $(1)
endif
.PHONY: $(2)-target-$(1)
$(2)-targets: $(2)-target-$(1)

endef

android-targets:
$(foreach target, $(ANDROID_TARGETS), $(eval $(call target-rules,$(target),android)))

ios-targets:
$(foreach target, $(IOS_TARGETS), $(eval $(call target-rules,$(target),ios)))

macos-targets:
$(foreach target, $(MACOS_TARGETS), $(eval $(call target-rules,$(target),macos)))

# Args:
# $1: OS name
# $2: Release mode
# $3: Rust target name 1
# $4: Rust target name 2
define lipo-rules

lipo-$(1)-$(2): $(1)-$(2)-$(3) $(1)-$(2)-$(4)
ifeq (,$(wildcard target/universal-$(1)/$(2)/$(FILENAME)))
	mkdir -p target/universal-$(1)/$(2)
	lipo target/$(3)/$(2)/$(FILENAME) target/$(4)/$(2)/$(FILENAME) -create -output target/universal-$(1)/$(2)/$(FILENAME)
endif

.PHONY: lipo-$(1)-$(2)

endef

$(eval $(call lipo-rules,macos,debug,$(word 1,$(MACOS_TARGETS)),$(word 2,$(MACOS_TARGETS))))
$(eval $(call lipo-rules,macos,release,$(word 1,$(MACOS_TARGETS)),$(word 2,$(MACOS_TARGETS))))
$(eval $(call lipo-rules,ios,debug,$(word 2,$(IOS_TARGETS)),$(word 3,$(IOS_TARGETS))))

.PHONY: android-install-deps cargo-ndk android-debug android-release android android-targets
.PHONY: ios-install-deps cbindgen ios-debug ios-release ios ios-targets
.PHONY: macos-install-deps macos-debug macos-release macos macos-targets
.PHONY: all
