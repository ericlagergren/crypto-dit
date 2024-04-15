use core::marker::PhantomData;

use cfg_if::cfg_if;

/// Shorthand for ensuring data independent timing (DIT) is
/// enabled for at least the current drop [scope].
///
/// It is permissible (and expected) to nest calls to
/// `enable!`; DIT will stay enabled until the outermost drop
/// scope ends.
///
/// # Examples
///
/// ```rust
/// use crypto_dit::enable;
///
/// fn encrypt_data() {
///     enable!();
///     // DIT will remain enabled until `encrypt_data` returns.
///     assert!(crypto_dit::is_enabled());
/// }
/// # if crypto_dit::is_supported() { encrypt_data() }
/// ```
///
/// As mentioned, calls can be nested:
///
/// ```rust
/// use crypto_dit::enable;
///
/// fn encrypt_data() {
///     enable!();
///     crypto_stuff();
///     // DIT remains enabled even though `crypto_stuff` also
///     // called `enable!`.
///     assert!(crypto_dit::is_enabled());
/// }
///
/// fn crypto_stuff() {
///     // Calling `enable!` twice is a no-op.
///     enable!();
///     assert!(crypto_dit::is_enabled());
/// }
/// # if crypto_dit::is_supported() { encrypt_data() }
/// ```
///
/// [scope]: https://doc.rust-lang.org/reference/destructors.html#drop-scopes
#[macro_export]
macro_rules! enable {
    () => {
        let _dit = $crate::enable();
    };
}

// Delegate to a CPU-specific implementation.
cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        use aarch64 as arch;
    } else {
        use generic as arch;
    }
}

/// Ensures data independent timing (DIT) is enabled for at least
/// the current drop [scope].
///
/// It is permissible (and expected) to nest calls to `enable`;
/// DIT will stay enabled until the outermost drop scope ends.
///
/// See [`enable!`] for an easier to use API.
///
/// # Examples
///
/// ```rust
/// use crypto_dit;
///
/// fn encrypt_data() {
///     let _dit = crypto_dit::enable();
///     // DIT will remain enabled until `encrypt_data` returns.
///     assert!(crypto_dit::is_enabled());
/// }
/// # if crypto_dit::is_supported() { encrypt_data() }
/// ```
///
/// As mentioned, calls can be nested:
///
/// ```rust
/// use crypto_dit;
///
/// fn encrypt_data() {
///     let _dit = crypto_dit::enable();
///     crypto_stuff();
///     // DIT remains enabled even though `crypto_stuff` also
///     // called `enable!`.
///     assert!(crypto_dit::is_enabled());
/// }
///
/// fn crypto_stuff() {
///     // Calling `enable` twice is a no-op.
///     crypto_dit::enable();
///     assert!(crypto_dit::is_enabled());
/// }
/// # if crypto_dit::is_supported() { encrypt_data() }
/// ```
///
/// [scope]: https://doc.rust-lang.org/reference/destructors.html#drop-scopes
#[inline(always)]
#[must_use]
pub fn enable() -> impl Drop {
    arch::enable()
}

/// Forcibly disables DIT, regardless of nested calls.
///
/// In general, you do not need to call this function unless you
/// do something silly like:
///
/// ```rust
/// use core::mem;
/// use crypto_dit;
///
/// # if crypto_dit::is_supported() {
/// let dit = crypto_dit::enable();
/// assert!(crypto_dit::is_enabled());
/// mem::forget(dit);
/// assert!(crypto_dit::is_enabled());
/// crypto_dit::disable();
/// assert!(!crypto_dit::is_enabled());
/// # }
/// ```
#[inline(always)]
pub fn disable() {
    arch::disable()
}

/// Reports whether the CPU supports DIT.
///
/// This method exists for informational purposes only. It is not
/// necessary to check whether DIT is supported before calling
/// [`enable()`] or [`enable!`].
#[inline(always)]
pub fn is_supported() -> bool {
    arch::is_supported()
}

/// Reports whether DIT is enabled.
///
/// This method exists for informational purposes only. It is not
/// necessary to check whether DIT is enabled before calling
/// [`enable()`] or [`enable!`].
#[inline(always)]
pub fn is_enabled() -> bool {
    arch::is_enabled()
}

// Ensure that `Dit` is always `!Send` and `!Sync`.
macro_rules! negative_impl {
    ($trait:ident) => {
        #[allow(clippy::undocumented_unsafe_blocks)]
        const _: () = {
            struct Dummy<'a, T: ?Sized>(PhantomData<&'a ()>, T);
            unsafe impl<T: ?Sized> $trait for Dummy<'_, T> where T: $trait {}
            #[allow(clippy::non_send_fields_in_send_ty, clippy::undocumented_unsafe_blocks)]
            unsafe impl<'a> $trait for arch::Dit where Dummy<'a, *const ()>: $trait {}
        };
    };
}
negative_impl!(Send);
negative_impl!(Sync);

/// See section C5.2.4 of "ARM Architecture Reference Manual
/// - ARMv8, for ARMv8-A architecture profile".
#[cfg(target_arch = "aarch64")]
mod aarch64 {
    #[must_use]
    #[clippy::has_significant_drop]
    pub(super) struct Dit {
        /// Did *we* enable DIT?
        enabled: bool,
    }

    impl Drop for Dit {
        #[inline(always)]
        fn drop(&mut self) {
            if self.enabled {
                debug_assert!(is_enabled());
                disable();
                debug_assert!(!is_enabled());
            }
        }
    }

    /// Conditionally enable DIT.
    #[inline(always)]
    pub fn enable() -> Dit {
        if !is_supported() {
            return Dit { enabled: false };
        }

        // SAFETY: we've checked `is_supported`.
        unsafe {
            if dit::is_enabled() {
                // Somebody else enabled DIT, so let them
                // disable it.
                return Dit { enabled: false };
            }
            dit::enable();
            debug_assert!(dit::is_enabled());
        }
        Dit { enabled: true }
    }

    /// Forcibly disables DIT.
    #[inline(always)]
    pub fn disable() {
        if !is_supported() {
            return;
        }
        // SAFETY: we've checked `is_supported`.
        unsafe {
            dit::disable();
            debug_assert!(!dit::is_enabled());
        }
    }

    pub use dit::is_supported;

    /// Is DIT enabled?
    #[inline(always)]
    pub fn is_enabled() -> bool {
        if !is_supported() {
            false
        } else {
            // SAFETY: we've checked `is_supported`.
            unsafe { dit::is_enabled() }
        }
    }

    mod dit {
        use core::arch::asm;

        use cfg_if::cfg_if;

        /// Enable DIT.
        ///
        /// # Safety
        ///
        /// DIT must be supported. Check with [`is_supported`].
        #[target_feature(enable = "dit")]
        pub unsafe fn enable() {
            // NB: we write out the opcode because DIT is v8.4+
            // and LLVM rejects the insructions when compiling
            // for older architectures.
            //
            // SAFETY: see section C5.2.4 of the reference
            // manual.
            unsafe {
                asm!(
                    ".inst 0xd503415f /* msr dit, #1 */",
                    options(nomem, nostack),
                )
            }
        }

        /// Disable DIT.
        ///
        /// # Safety
        ///
        /// DIT must be supported. Check with [`is_supported`].
        #[target_feature(enable = "dit")]
        pub unsafe fn disable() {
            // NB: we write out the opcode because DIT is v8.4+
            // and LLVM rejects the insructions when compiling
            // for older architectures.
            //
            // SAFETY: see section C5.2.4 of the reference
            // manual.
            unsafe {
                asm!(
                    ".inst 0xd503405f /* msr dit, #0 */",
                    options(nomem, nostack),
                )
            }
        }

        /// Is DIT enabled?
        ///
        /// # Safety
        ///
        /// DIT must be supported. Check with [`is_supported`].
        #[target_feature(enable = "dit")]
        pub unsafe fn is_enabled() -> bool {
            let dit: u64;
            // NB: we write out the opcode because DIT is v8.4+
            // and LLVM rejects the insructions when compiling
            // for older architectures.
            //
            // SAFETY: see section C5.2.4 of the reference
            // manual.
            unsafe {
                asm!(
                    ".inst 0xd53b42a8 /* mrs x8, dit */",
                    out("x8") dit,
                    options(nomem, nostack),
                )
            }
            dit & (1 << 24) != 0
        }

        cfg_if! {
            if #[cfg(all(
                    target_os = "linux",
                    any(target_env = "gnu", target_env = "musl", taget_env = "android")
                ))] {
                pub use linux::is_supported;
            } else if #[cfg(target_os = "macos")] {
                pub use macos::is_supported;
            } else {
                #[inline(always)]
                pub fn is_supported() -> bool {
                    // Reading the machine system register is
                    // (usually) privileged, so without OS
                    // support there isn't much we can do here.
                    false
                }
            }
        }

        #[cfg(all(
            target_os = "linux",
            any(target_env = "gnu", target_env = "musl", taget_env = "android")
        ))]
        mod linux {
            /// Does the CPU support DIT?
            #[inline(always)]
            pub fn is_supported() -> bool {
                use super::atomic::Once;

                // No clue how fast `getauxval` is, but other
                // libraries like BoringSSL cache its result.
                static IS_SUPPORTED: Once = Once::new();

                IS_SUPPORTED.call_once_ish(|| {
                    // SAFETY: FFI call, no invariants.
                    let value = unsafe { libc::getauxval(libc::AT_HWCAP) };
                    value & libc::HWCAP_DIT != 0
                })
            }
        }

        #[cfg(target_os = "macos")]
        mod macos {
            use core::ptr;

            use cfg_if::cfg_if;

            /// Does this CPU support DIT?
            #[inline(always)]
            pub fn is_supported() -> bool {
                cfg_if! {
                    if #[cfg(feature = "libc")] {
                        is_supported_sysctl()
                    } else {
                        is_supported_commpage()
                    }
                }
            }

            #[cfg(any(test, not(feature = "libc")))]
            #[inline(always)]
            fn is_supported_commpage() -> bool {
                // NB: we use commpage instead of `sysctlbyname`
                // by default  because it's faster (compiles down
                // to a load and test), simpler (doesn't require
                // libc), and used by other languages/libraries,
                // including corecrypto itself.

                // Constants are from
                // https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/arm/cpu_capabilities.h
                const _COMM_PAGE64_BASE_ADDRESS: u64 = 0x0000000FFFFFC000;
                const _COMM_PAGE_START_ADDRESS: u64 = _COMM_PAGE64_BASE_ADDRESS;
                const _COMM_PAGE_CPU_CAPABILITIES64: u64 = _COMM_PAGE_START_ADDRESS + 0x010;
                const K_HAS_FEAT_DIT: u64 = 0x0200000000000000;

                // SAFETY: the pointer is valid for reads, it's
                // aligned, and it's properly initialized.
                let caps =
                    unsafe { ptr::read_volatile(_COMM_PAGE_CPU_CAPABILITIES64 as *const u64) };
                caps & K_HAS_FEAT_DIT != 0
            }

            /// The "official" method of checking for DIT
            /// support.
            ///
            /// See <https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms#Enable-DIT-for-constant-time-cryptographic-operations>
            #[cfg(any(test, feature = "libc"))]
            #[inline(always)]
            fn is_supported_sysctl() -> bool {
                use super::atomic::Once;

                static IS_SUPPORTED: Once = Once::new();

                IS_SUPPORTED.call_once_ish(|| {
                    let mut has_dit: i32 = 0;
                    let mut has_dit_size = ::core::mem::size_of_val(&has_dit);
                    // SAFETY: FFI call, no invariants.
                    let ret = unsafe {
                        ::libc::sysctlbyname(
                            "hw.optional.arm.FEAT_DIT\0".as_ptr().cast(),
                            ptr::addr_of_mut!(has_dit).cast(),
                            ptr::addr_of_mut!(has_dit_size),
                            ptr::null_mut(),
                            0,
                        )
                    };
                    ret >= 0 && has_dit != 0
                })
            }

            #[cfg(test)]
            mod tests {
                use super::*;

                /// Tests that [`is_supported`] matches Apple's
                /// official recommendation for checking DIT
                /// support.
                #[test]
                fn test_is_supported() {
                    assert_eq!(is_supported_commpage(), is_supported_sysctl());
                }
            }
        }

        #[cfg(any(
            all(target_os = "macos", any(test, feature = "libc")),
            all(
                target_os = "linux",
                any(target_env = "gnu", target_env = "musl", taget_env = "android")
            )
        ))]
        mod atomic {
            use core::sync::atomic::{AtomicU32, Ordering};

            pub struct Once(AtomicU32);

            impl Once {
                const UNKNOWN: u32 = u32::MAX;

                pub const fn new() -> Self {
                    Self(AtomicU32::new(Self::UNKNOWN))
                }

                pub fn call_once_ish<F>(&self, mut f: F) -> bool
                where
                    F: FnMut() -> bool,
                {
                    let value =
                        match self
                            .0
                            .fetch_update(Ordering::SeqCst, Ordering::Relaxed, |v| {
                                if v == Self::UNKNOWN {
                                    Some(f() as u32)
                                } else {
                                    Some(v)
                                }
                            }) {
                            Ok(v) | Err(v) => v,
                        };
                    value == 1
                }
            }
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
mod generic {
    pub(super) struct Dit(());

    impl Drop for Dit {
        fn drop(&mut self) {}
    }

    pub fn enable() -> Dit {
        Dit(())
    }

    pub fn disable() {}

    pub fn is_supported() -> bool {
        false
    }

    pub fn is_enabled() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use core::mem;
    use std::thread;

    use super::*;

    macro_rules! check_support {
        () => {
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
                assert!(is_supported());
            }
            if !is_supported() {
                std::eprintln!("DIT not supported");
                return;
            }
        };
    }

    /// Basic test for enabling DIT.
    #[test]
    fn test_enable() {
        check_support!();

        let dit = enable();
        assert!(is_enabled());
        drop(dit);
        assert!(!is_enabled());
    }

    /// Basic test for enabling DIT in a block.
    #[test]
    fn test_enable_block_scope() {
        check_support!();

        {
            let _dit = enable();
            assert!(is_enabled());
        }
        assert!(!is_enabled());
    }

    /// Basic test for enabling DIT in a function.
    #[test]
    fn test_enable_fn_scope() {
        check_support!();

        fn foo() {
            let _dit = enable();
            assert!(is_enabled());
        }
        foo();
        assert!(!is_enabled());
    }

    /// Test when DIT is already enabled.
    #[test]
    fn test_already_enabled() {
        check_support!();

        let dit1 = enable();
        let dit2 = enable();
        assert!(is_enabled());
        drop(dit2);
        assert!(is_enabled());
        drop(dit1);
        assert!(!is_enabled());
    }

    /// Basic test for [`disable`].
    #[test]
    fn test_disable() {
        check_support!();

        let dit = enable();
        assert!(is_enabled());
        mem::forget(dit);
        assert!(is_enabled());
        disable();
        assert!(!is_enabled());
    }

    /// Test that DIT support is per-thread.
    #[test]
    fn test_multi_thread() {
        check_support!();

        enable!();
        assert!(is_enabled());
        let disabled = thread::spawn(is_enabled);
        let enabled = thread::spawn(|| {
            assert!(!is_enabled());
            enable!();
            is_enabled()
        });
        assert!(!disabled.join().unwrap());
        assert!(enabled.join().unwrap());
        assert!(is_enabled());
    }

    // #[test]
    // fn test_not_send() {
    //     fn is_send<T: Send>(_: T) {}
    //     fn is_sync<T: Sync>(_: T) {}
    //     is_send(enable());
    //     is_sync(enable());
    // }
}
