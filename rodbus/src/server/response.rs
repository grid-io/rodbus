use crate::common::cursor::WriteCursor;
use crate::common::function::FunctionCode;
use crate::common::traits::Serialize;
use crate::error::RequestError;
use crate::exception::ExceptionCode;
use crate::types::{ReadBitsRange, ReadRegistersRange};

pub(crate) struct BitWriter<T>
where
    T: Fn(u16) -> Result<bool, ExceptionCode>,
{
    pub(crate) range: ReadBitsRange,
    pub(crate) getter: T,
}

impl<T> BitWriter<T>
where
    T: Fn(u16) -> Result<bool, ExceptionCode>,
{
    pub(crate) fn new(range: ReadBitsRange, getter: T) -> Self {
        Self { range, getter }
    }
}

pub(crate) struct RegisterWriter<T>
where
    T: Fn(u16) -> Result<u16, ExceptionCode>,
{
    pub(crate) range: ReadRegistersRange,
    pub(crate) getter: T,
}

impl<T> RegisterWriter<T>
where
    T: Fn(u16) -> Result<u16, ExceptionCode>,
{
    pub(crate) fn new(range: ReadRegistersRange, getter: T) -> Self {
        Self { range, getter }
    }
}

pub(crate) struct ErrorResponse {
    pub(crate) function: u8,
    pub(crate) exception: ExceptionCode,
}

impl ErrorResponse {
    pub(crate) fn new(function: FunctionCode, exception: ExceptionCode) -> Self {
        ErrorResponse {
            function: function.as_error(),
            exception,
        }
    }

    pub(crate) fn unknown_function(unknown: u8) -> Self {
        ErrorResponse {
            function: unknown | 0x80,
            exception: ExceptionCode::IllegalFunction,
        }
    }
}

impl Serialize for ErrorResponse {
    fn serialize(&self, cursor: &mut WriteCursor) -> Result<(), RequestError> {
        cursor.write_u8(self.function)?;
        self.exception.serialize(cursor)?;
        Ok(())
    }
}
