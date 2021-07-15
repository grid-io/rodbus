use crate::ffi;
use rodbus::client::channel::{CallbackSession, RequestParam};
use rodbus::types::UnitId;
use std::time::Duration;

impl ffi::RequestParam {
    pub(crate) fn build_session(&self, channel: &crate::Channel) -> CallbackSession {
        CallbackSession::new(
            channel.inner.clone(),
            RequestParam::new(
                UnitId::new(self.unit_id),
                Duration::from_millis(self.timeout_ms as u64),
            ),
        )
    }
}

impl ffi::BitReadCallback {
    pub(crate) fn convert_to_fn_once(
        self,
    ) -> impl FnOnce(std::result::Result<rodbus::types::BitIterator, rodbus::error::Error>) {
        move |result: std::result::Result<rodbus::types::BitIterator, rodbus::error::Error>| {
            match result {
                Err(err) => {
                    self.on_complete(err.into());
                }
                Ok(values) => {
                    let mut iter = crate::BitIterator::new(values);

                    let result = ffi::BitReadResult {
                        result: ffi::ErrorInfo::success(),
                        iterator: &mut iter as *mut crate::BitIterator,
                    };

                    self.on_complete(result);
                }
            }
        }
    }
}

impl ffi::RegisterReadCallback {
    pub(crate) fn convert_to_fn_once(
        self,
    ) -> impl FnOnce(std::result::Result<rodbus::types::RegisterIterator, rodbus::error::Error>)
    {
        move |result: std::result::Result<rodbus::types::RegisterIterator, rodbus::error::Error>| {
            match result {
                Err(err) => {
                    self.on_complete(err.into());
                }
                Ok(values) => {
                    let mut iter = crate::RegisterIterator::new(values);

                    let result = ffi::RegisterReadResult {
                        result: ffi::ErrorInfo::success(),
                        iterator: &mut iter as *mut crate::RegisterIterator,
                    };

                    self.on_complete(result);
                }
            }
        }
    }
}

impl ffi::WriteCallback {
    /// we do't care what type T is b/c we're going to ignore it
    pub(crate) fn convert_to_fn_once<T>(
        self,
    ) -> impl FnOnce(std::result::Result<T, rodbus::error::Error>) {
        move |result: std::result::Result<T, rodbus::error::Error>| match result {
            Err(err) => {
                self.on_complete(err.into());
            }
            Ok(_) => {
                self.on_complete(ffi::ErrorInfo::success());
            }
        }
    }
}

impl ffi::ErrorInfo {
    pub(crate) fn success() -> Self {
        ffi::ErrorInfoFields {
            summary: ffi::Status::Ok,
            exception: ffi::ModbusException::Unknown,
            raw_exception: 0,
        }
        .into()
    }
}

impl ffi::WriteResult {
    pub(crate) fn convert_to_result(self) -> Result<(), rodbus::exception::ExceptionCode> {
        if self.success() {
            return Ok(());
        }
        let ex = match self.exception() {
            ffi::ModbusException::Acknowledge => rodbus::exception::ExceptionCode::Acknowledge,
            ffi::ModbusException::GatewayPathUnavailable => {
                rodbus::exception::ExceptionCode::GatewayPathUnavailable
            }
            ffi::ModbusException::GatewayTargetDeviceFailedToRespond => {
                rodbus::exception::ExceptionCode::GatewayTargetDeviceFailedToRespond
            }
            ffi::ModbusException::IllegalDataAddress => {
                rodbus::exception::ExceptionCode::IllegalDataAddress
            }
            ffi::ModbusException::IllegalDataValue => {
                rodbus::exception::ExceptionCode::IllegalDataValue
            }
            ffi::ModbusException::IllegalFunction => {
                rodbus::exception::ExceptionCode::IllegalFunction
            }
            ffi::ModbusException::MemoryParityError => {
                rodbus::exception::ExceptionCode::MemoryParityError
            }
            ffi::ModbusException::ServerDeviceBusy => {
                rodbus::exception::ExceptionCode::ServerDeviceBusy
            }
            ffi::ModbusException::ServerDeviceFailure => {
                rodbus::exception::ExceptionCode::ServerDeviceFailure
            }
            ffi::ModbusException::Unknown => {
                rodbus::exception::ExceptionCode::Unknown(self.raw_exception())
            }
        };

        Err(ex)
    }
}
