use std::path::Path;

use crate::ffi;
use rodbus::client::{ReconnectStrategy, WriteMultiple};
use rodbus::AddressRange;

pub struct Channel {
    pub(crate) inner: rodbus::client::Channel,
    pub(crate) runtime: crate::RuntimeHandle,
}

pub(crate) unsafe fn create_tcp_client(
    runtime: *mut crate::Runtime,
    address: &std::ffi::CStr,
    max_queued_requests: u16,
    retry_strategy: ffi::RetryStrategy,
    decode_level: ffi::DecodeLevel,
) -> Result<*mut crate::Channel, ffi::ParamError> {
    let runtime = runtime.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let address = address.to_string_lossy().parse()?;

    let (handle, task) = rodbus::client::create_tcp_handle_and_task(
        address,
        max_queued_requests as usize,
        retry_strategy.into(),
        decode_level.into(),
    );

    runtime.inner.spawn(task);

    Ok(Box::into_raw(Box::new(Channel {
        inner: handle,
        runtime: runtime.handle(),
    })))
}

pub(crate) unsafe fn create_tls_client(
    runtime: *mut crate::Runtime,
    address: &std::ffi::CStr,
    max_queued_requests: u16,
    retry_strategy: ffi::RetryStrategy,
    tls_config: ffi::TlsClientConfig,
    decode_level: ffi::DecodeLevel,
) -> Result<*mut crate::Channel, ffi::ParamError> {
    let runtime = runtime.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let address = address.to_string_lossy().parse()?;

    let password = tls_config.password().to_string_lossy();
    let optional_password = match password.as_ref() {
        "" => None,
        password => Some(password),
    };

    let tls_config = rodbus::client::TlsClientConfig::new(
        &tls_config.dns_name().to_string_lossy(),
        Path::new(tls_config.peer_cert_path().to_string_lossy().as_ref()),
        Path::new(tls_config.local_cert_path().to_string_lossy().as_ref()),
        Path::new(tls_config.private_key_path().to_string_lossy().as_ref()),
        optional_password,
        tls_config.min_tls_version().into(),
        tls_config.certificate_mode().into(),
    )
    .map_err(|err| {
        tracing::error!("TLS error: {}", err);
        err
    })?;

    let (handle, task) = rodbus::client::create_tls_handle_and_task(
        address,
        max_queued_requests as usize,
        retry_strategy.into(),
        tls_config,
        decode_level.into(),
    );

    runtime.inner.spawn(task);

    Ok(Box::into_raw(Box::new(Channel {
        inner: handle,
        runtime: runtime.handle(),
    })))
}

pub(crate) unsafe fn channel_destroy(channel: *mut crate::Channel) {
    if !channel.is_null() {
        Box::from_raw(channel);
    };
}

pub(crate) unsafe fn channel_read_coils(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    range: crate::ffi::AddressRange,
    callback: crate::ffi::BitReadCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let range = AddressRange::try_from(range.start, range.count)?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.read_coils(range, callback).await })?;

    Ok(())
}

pub(crate) unsafe fn channel_read_discrete_inputs(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    range: crate::ffi::AddressRange,
    callback: crate::ffi::BitReadCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let range = AddressRange::try_from(range.start, range.count)?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.read_discrete_inputs(range, callback).await })?;

    Ok(())
}

pub(crate) unsafe fn channel_read_holding_registers(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    range: crate::ffi::AddressRange,
    callback: crate::ffi::RegisterReadCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let range = AddressRange::try_from(range.start, range.count)?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.read_holding_registers(range, callback).await })?;

    Ok(())
}

pub(crate) unsafe fn channel_read_input_registers(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    range: crate::ffi::AddressRange,
    callback: crate::ffi::RegisterReadCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let range = AddressRange::try_from(range.start, range.count)?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.read_input_registers(range, callback).await })?;

    Ok(())
}

pub(crate) unsafe fn channel_write_single_coil(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    bit: crate::ffi::Bit,
    callback: crate::ffi::WriteCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.write_single_coil(bit.into(), callback).await })?;

    Ok(())
}

pub(crate) unsafe fn channel_write_single_register(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    register: crate::ffi::Register,
    callback: crate::ffi::WriteCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel.runtime.spawn(async move {
        session
            .write_single_register(register.into(), callback)
            .await
    })?;

    Ok(())
}

pub(crate) unsafe fn channel_write_multiple_coils(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    start: u16,
    items: *mut crate::BitList,
    callback: crate::ffi::WriteCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let items = items.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let args = WriteMultiple::from(start, items.inner.clone())?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.write_multiple_coils(args, callback).await })?;

    Ok(())
}

pub(crate) unsafe fn channel_write_multiple_registers(
    channel: *mut crate::Channel,
    param: crate::ffi::RequestParam,
    start: u16,
    items: *mut crate::RegisterList,
    callback: crate::ffi::WriteCallback,
) -> Result<(), ffi::ParamError> {
    let channel = channel.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let items = items.as_ref().ok_or(ffi::ParamError::NullParameter)?;
    let args = WriteMultiple::from(start, items.inner.clone())?;
    let callback = callback.convert_to_fn_once();

    let mut session = param.build_session(channel);
    channel
        .runtime
        .spawn(async move { session.write_multiple_registers(args, callback).await })?;

    Ok(())
}

impl From<ffi::RetryStrategy> for Box<dyn ReconnectStrategy + Send> {
    fn from(from: ffi::RetryStrategy) -> Self {
        rodbus::client::doubling_reconnect_strategy(from.min_delay(), from.max_delay())
    }
}
