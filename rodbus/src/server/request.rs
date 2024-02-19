use crate::common::frame::{FrameHeader, FrameWriter, FunctionField};
use crate::common::function::FunctionCode;
use crate::common::traits::{Loggable, Parse, Serialize};
use crate::decode::AppDecodeLevel;
use crate::error::RequestError;
use crate::exception::ExceptionCode;
use crate::server::handler::RequestHandler;
use crate::server::response::{BitWriter, RegisterWriter};
use crate::server::*;
use crate::types::*;

use scursor::ReadCursor;

#[derive(Debug)]
pub(crate) enum Request<'a> {
    ReadCoils(ReadBitsRange),
    ReadDiscreteInputs(ReadBitsRange),
    ReadHoldingRegisters(ReadRegistersRange),
    ReadInputRegisters(ReadRegistersRange),
    WriteSingleCoil(Indexed<bool>),
    WriteSingleRegister(Indexed<u16>),
    WriteMultipleCoils(WriteCoils<'a>),
    WriteMultipleRegisters(WriteRegisters<'a>),
    ReadWriteMultipleRegisters(ReadWriteRegisters<'a>),
    WriteCustomFunctionCode(CustomFunctionCode),
}

/// All requests that support broadcast
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum BroadcastRequest<'a> {
    WriteSingleCoil(Indexed<bool>),
    WriteSingleRegister(Indexed<u16>),
    WriteMultipleCoils(WriteCoils<'a>),
    WriteMultipleRegisters(WriteRegisters<'a>),
}

impl<'a> BroadcastRequest<'a> {
    // execute a broadcast request against the handler
    pub(crate) fn execute<T: RequestHandler>(&self, handler: &mut T) {
        match self {
            BroadcastRequest::WriteSingleCoil(x) => {
                let _ = handler.write_single_coil(*x);
            }
            BroadcastRequest::WriteSingleRegister(x) => {
                let _ = handler.write_single_register(*x);
            }
            BroadcastRequest::WriteMultipleCoils(x) => {
                let _ = handler.write_multiple_coils(*x);
            }
            BroadcastRequest::WriteMultipleRegisters(x) => {
                let _ = handler.write_multiple_registers(*x);
            }
        }
    }
}

impl<'a> Request<'a> {
    pub(crate) fn get_function(&self) -> FunctionCode {
        match self {
            Request::ReadCoils(_) => FunctionCode::ReadCoils,
            Request::ReadDiscreteInputs(_) => FunctionCode::ReadDiscreteInputs,
            Request::ReadHoldingRegisters(_) => FunctionCode::ReadHoldingRegisters,
            Request::ReadInputRegisters(_) => FunctionCode::ReadInputRegisters,
            Request::WriteSingleCoil(_) => FunctionCode::WriteSingleCoil,
            Request::WriteSingleRegister(_) => FunctionCode::WriteSingleRegister,
            Request::WriteMultipleCoils(_) => FunctionCode::WriteMultipleCoils,
            Request::WriteMultipleRegisters(_) => FunctionCode::WriteMultipleRegisters,
            Request::ReadWriteMultipleRegisters(_) => FunctionCode::ReadWriteMultipleRegisters,
            Request::WriteCustomFunctionCode(_) => FunctionCode::WriteCustomFunctionCode,
        }
    }

    pub(crate) fn into_broadcast_request(self) -> Option<BroadcastRequest<'a>> {
        match self {
            Request::ReadCoils(_) => None,
            Request::ReadDiscreteInputs(_) => None,
            Request::ReadHoldingRegisters(_) => None,
            Request::ReadInputRegisters(_) => None,
            Request::WriteSingleCoil(x) => Some(BroadcastRequest::WriteSingleCoil(x)),
            Request::WriteSingleRegister(x) => Some(BroadcastRequest::WriteSingleRegister(x)),
            Request::WriteMultipleCoils(x) => Some(BroadcastRequest::WriteMultipleCoils(x)),
            Request::WriteMultipleRegisters(x) => Some(BroadcastRequest::WriteMultipleRegisters(x)),
            Request::ReadWriteMultipleRegisters(_) => None,
            Request::WriteCustomFunctionCode(_) => None,
        }
    }

    pub(crate) fn get_reply<'b>(
        &self,
        header: FrameHeader,
        handler: &mut dyn RequestHandler,
        writer: &'b mut FrameWriter,
        level: DecodeLevel,
    ) -> Result<&'b [u8], RequestError> {
        fn write_result<T>(
            function: FunctionCode,
            header: FrameHeader,
            writer: &mut FrameWriter,
            result: Result<T, ExceptionCode>,
            level: DecodeLevel,
        ) -> Result<&[u8], RequestError>
        where
            T: Serialize + Loggable,
        {
            match result {
                Ok(response) => writer.format_reply(header, function, &response, level),
                Err(ex) => writer.format_ex(header, FunctionField::Exception(function), ex, level),
            }
        }

        let function = self.get_function();

        // make a first pass effort to serialize a response
        match self {
            Request::ReadCoils(range) => {
                let bits = BitWriter::new(*range, |i| handler.read_coil(i));
                writer.format_reply(header, function, &bits, level)
            }
            Request::ReadDiscreteInputs(range) => {
                let bits = BitWriter::new(*range, |i| handler.read_discrete_input(i));
                writer.format_reply(header, function, &bits, level)
            }
            Request::ReadHoldingRegisters(range) => {
                let registers = RegisterWriter::new(*range, |i| handler.read_holding_register(i));
                writer.format_reply(header, function, &registers, level)
            }
            Request::ReadInputRegisters(range) => {
                let registers = RegisterWriter::new(*range, |i| handler.read_input_register(i));
                writer.format_reply(header, function, &registers, level)
            }
            Request::WriteSingleCoil(request) => {
                let result = handler.write_single_coil(*request).map(|_| *request);
                write_result(function, header, writer, result, level)
            }
            Request::WriteSingleRegister(request) => {
                let result = handler.write_single_register(*request).map(|_| *request);
                write_result(function, header, writer, result, level)
            }
            Request::WriteMultipleCoils(items) => {
                let result = handler.write_multiple_coils(*items).map(|_| items.range);
                write_result(function, header, writer, result, level)
            }
            Request::WriteMultipleRegisters(items) => {
                let result = handler
                    .write_multiple_registers(*items)
                    .map(|_| items.range);
                write_result(function, header, writer, result, level)
            }
            Request::ReadWriteMultipleRegisters(items) => {
                let write_registers = &WriteRegisters::new(items.write_range, items.iterator);
                let _ = handler.write_multiple_registers(*write_registers).map(|_| write_registers.range);
                
                let read_registers = ReadRegistersRange{ inner: items.read_range };
                let read_res = RegisterWriter::new(read_registers, |i| handler.read_holding_register(i));
                writer.format_reply(header, function, &read_res, level)
            }
            Request::WriteCustomFunctionCode(request) => {
                let result = handler.write_custom_function_code(*request).map(|_| *request);
                write_result(function, header, writer, result, level)
            }
        }
    }

    pub(crate) fn parse(
        function: FunctionCode,
        cursor: &'a mut ReadCursor,
    ) -> Result<Self, RequestError> {
        match function {
            FunctionCode::ReadCoils => {
                let x = Request::ReadCoils(AddressRange::parse(cursor)?.of_read_bits()?);
                cursor.expect_empty()?;
                Ok(x)
            }
            FunctionCode::ReadDiscreteInputs => {
                let x = Request::ReadDiscreteInputs(AddressRange::parse(cursor)?.of_read_bits()?);
                cursor.expect_empty()?;
                Ok(x)
            }
            FunctionCode::ReadHoldingRegisters => {
                let x = Request::ReadHoldingRegisters(
                    AddressRange::parse(cursor)?.of_read_registers()?,
                );
                cursor.expect_empty()?;
                Ok(x)
            }
            FunctionCode::ReadInputRegisters => {
                let x =
                    Request::ReadInputRegisters(AddressRange::parse(cursor)?.of_read_registers()?);
                cursor.expect_empty()?;
                Ok(x)
            }
            FunctionCode::WriteSingleCoil => {
                let x = Request::WriteSingleCoil(Indexed::<bool>::parse(cursor)?);
                cursor.expect_empty()?;
                Ok(x)
            }
            FunctionCode::WriteSingleRegister => {
                let x = Request::WriteSingleRegister(Indexed::<u16>::parse(cursor)?);
                cursor.expect_empty()?;
                Ok(x)
            }
            FunctionCode::WriteMultipleCoils => {
                let range = AddressRange::parse(cursor)?;
                // don't care about the count, validated b/c all bytes are consumed
                cursor.read_u8()?;
                Ok(Request::WriteMultipleCoils(WriteCoils::new(
                    range,
                    BitIterator::parse_all(range, cursor)?,
                )))
            }
            FunctionCode::WriteMultipleRegisters => {
                let range = AddressRange::parse(cursor)?;
                // don't care about the count, validated b/c all bytes are consumed
                cursor.read_u8()?;
                Ok(Request::WriteMultipleRegisters(WriteRegisters::new(
                    range,
                    RegisterIterator::parse_all(range, cursor)?,
                )))
            }
            FunctionCode::ReadWriteMultipleRegisters => {
                let read_range = AddressRange::parse(cursor)?;
                let write_range = AddressRange::parse(cursor)?;
                // don't care about the count, validated b/c all bytes are consumed
                cursor.read_u8()?;
                let iterator = RegisterIterator::parse_all(write_range, cursor)?;
                let read_write_registers = ReadWriteRegisters::new(
                    read_range,
                    write_range,
                    iterator,
                );
                Ok(Request::ReadWriteMultipleRegisters(read_write_registers))
            }
            FunctionCode::WriteCustomFunctionCode => {
                let x =
                    Request::WriteCustomFunctionCode(CustomFunctionCode::parse(cursor)?);
                cursor.expect_empty()?;
                Ok(x)
            }
        }
    }
}

pub(crate) struct RequestDisplay<'a, 'b> {
    request: &'a Request<'b>,
    level: AppDecodeLevel,
}

impl<'a, 'b> RequestDisplay<'a, 'b> {
    pub(crate) fn new(level: AppDecodeLevel, request: &'a Request<'b>) -> Self {
        Self { request, level }
    }
}

impl std::fmt::Display for RequestDisplay<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.request.get_function())?;

        if self.level.data_headers() {
            match self.request {
                Request::ReadCoils(range) => {
                    write!(f, " {}", range.get())?;
                }
                Request::ReadDiscreteInputs(range) => {
                    write!(f, " {}", range.get())?;
                }
                Request::ReadHoldingRegisters(range) => {
                    write!(f, " {}", range.get())?;
                }
                Request::ReadInputRegisters(range) => {
                    write!(f, " {}", range.get())?;
                }
                Request::WriteSingleCoil(request) => {
                    write!(f, " {request}")?;
                }
                Request::WriteSingleRegister(request) => {
                    write!(f, " {request}")?;
                }
                Request::WriteMultipleCoils(items) => {
                    write!(
                        f,
                        " {}",
                        BitIteratorDisplay::new(self.level, items.iterator)
                    )?;
                }
                Request::WriteMultipleRegisters(items) => {
                    write!(
                        f,
                        " {}",
                        RegisterIteratorDisplay::new(self.level, items.iterator)
                    )?;
                }
                Request::ReadWriteMultipleRegisters(request) => {
                    write!(
                        f,
                        " {} {} {}",
                        request.read_range,
                        request.write_range,
                        RegisterIteratorDisplay::new(self.level, request.iterator)
                    )?;
                }
                Request::WriteCustomFunctionCode(request) => {
                    write!(f, " {request}")?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod coils {
        use scursor::ReadCursor;

        use super::super::*;
        use crate::error::AduParseError;
        use crate::types::Indexed;

        #[test]
        fn fails_when_too_few_bytes_for_coil_byte_count() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x08, 0x00]);
            let err = Request::parse(FunctionCode::WriteMultipleCoils, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn fails_when_too_many_bytes_for_coil_byte_count() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x08, 0x02]);
            let err = Request::parse(FunctionCode::WriteMultipleCoils, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn fails_when_specified_byte_count_not_present() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x08, 0x01]);
            let err = Request::parse(FunctionCode::WriteMultipleCoils, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn fails_when_too_many_bytes_present() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x08, 0x01, 0xFF, 0xFF]);
            let err = Request::parse(FunctionCode::WriteMultipleCoils, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::TrailingBytes(1).into());
        }

        #[test]
        fn can_parse_coils() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x03, 0x01, 0x05]);
            let coils = match Request::parse(FunctionCode::WriteMultipleCoils, &mut cursor).unwrap()
            {
                Request::WriteMultipleCoils(write) => write,
                _ => panic!("bad match"),
            };

            assert_eq!(coils.range, AddressRange::try_from(1, 3).unwrap());
            assert_eq!(
                coils.iterator.collect::<Vec<Indexed<bool>>>(),
                vec![
                    Indexed::new(1, true),
                    Indexed::new(2, false,),
                    Indexed::new(3, true)
                ]
            )
        }
    }

    mod registers {
        use scursor::ReadCursor;

        use super::super::*;
        use crate::error::AduParseError;
        use crate::types::Indexed;

        #[test]
        fn fails_when_too_few_bytes_for_coil_byte_count() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x01, 0x00]);
            let err = Request::parse(FunctionCode::WriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn fails_when_too_many_bytes_for_coil_byte_count() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x01, 0x03]);
            let err = Request::parse(FunctionCode::WriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn fails_when_specified_byte_count_not_present() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x01, 0x02, 0xFF]);
            let err = Request::parse(FunctionCode::WriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn fails_when_too_many_bytes_present() {
            let mut cursor = ReadCursor::new(&[0x00, 0x01, 0x00, 0x01, 0x02, 0xFF, 0xFF, 0xFF]);
            let err = Request::parse(FunctionCode::WriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::TrailingBytes(1).into());
        }

        #[test]
        fn can_parse_registers() {
            let mut cursor =
                ReadCursor::new(&[0x00, 0x01, 0x00, 0x02, 0x04, 0xCA, 0xFE, 0xBB, 0xDD]);
            let registers =
                match Request::parse(FunctionCode::WriteMultipleRegisters, &mut cursor).unwrap() {
                    Request::WriteMultipleRegisters(write) => write,
                    _ => panic!("bad match"),
                };

            assert_eq!(registers.range, AddressRange::try_from(1, 2).unwrap());
            assert_eq!(
                registers.iterator.collect::<Vec<Indexed<u16>>>(),
                vec![Indexed::new(1, 0xCAFE), Indexed::new(2, 0xBBDD)]
            )
        }
    }

    mod read_write_multiple_registers {    
        use scursor::ReadCursor;

        use super::super::*;
        use crate::error::AduParseError;
    
        //ANCHOR: parse read_write_multiple_request
    
        /// Write a single zero value to register 1 (index 0) - Minimum test
        /// Read 5 registers starting at register 1 (index 0-4) afterwards
        /// 
        /// read_range  start: 0x00, count: 0x05
        /// write_range start: 0x00, count: 0x01
        /// value length = 2 bytes, value = 0x0000
        #[test]
        fn can_parse_read_write_multiple_registers_request_of_single_zero_register_write() {
            let mut cursor = ReadCursor::new(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00]);
            let registers = match Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor).unwrap() {
                Request::ReadWriteMultipleRegisters(registers) => registers,
                _ => panic!("bad match"),
            };
            assert_eq!(registers.read_range, AddressRange::try_from(0x00, 0x05).unwrap());
            assert_eq!(registers.write_range, AddressRange::try_from(0x00, 0x01).unwrap());
            assert_eq!(registers.iterator.collect::<Vec<Indexed<u16>>>(), vec![Indexed::new(0x0000, 0x0000)]);
        }
    
        /// Write a single 0xFFFF value to register 0xFFFF (index 65.535) - Limit test
        /// Read 5 registers starting at register 0xFFFB (65.531-65.535) afterwards
        /// 
        /// read_range  start: 0xFFFB, count: 0x05
        /// write_range start: 0xFFFF, count: 0x01
        /// value length = 2 bytes, value = 0xFFFF
        #[test]
        fn can_parse_read_write_multiple_registers_request_of_single_u16_register_write() {
            let mut cursor = ReadCursor::new(&[0xFF, 0xFB, 0x00, 0x05, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0xFF, 0xFF]);
            let registers = match Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor).unwrap() {
                Request::ReadWriteMultipleRegisters(registers) => registers,
                _ => panic!("bad match"),
            };
            assert_eq!(registers.read_range, AddressRange::try_from(0xFFFB, 0x05).unwrap());
            assert_eq!(registers.write_range, AddressRange::try_from(0xFFFF, 0x01).unwrap());
            assert_eq!(registers.iterator.collect::<Vec<Indexed<u16>>>(), vec![Indexed::new(0xFFFF, 0xFFFF)]);
        }
    
        /// Write multiple zero values to registers 1, 2 and 3 (index 0-2) - Minimum test
        /// Read 5 registers starting at register 1 (0-4) afterwards
        /// 
        /// read_range  start: 0x00, count: 0x05
        /// write_range start: 0x00, count: 0x03
        /// values length = 6 bytes, values = 0x0000, 0x0000, 0x0000
        #[test]
        fn can_parse_read_write_multiple_registers_request_of_multiple_zero_register_write() {
            let mut cursor = ReadCursor::new(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            let registers = match Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor).unwrap() {
                Request::ReadWriteMultipleRegisters(registers) => registers,
                _ => panic!("bad match"),
            };
            assert_eq!(registers.read_range, AddressRange::try_from(0x00, 0x05).unwrap());
            assert_eq!(registers.write_range, AddressRange::try_from(0x00, 0x03).unwrap());
            assert_eq!(registers.iterator.collect::<Vec<Indexed<u16>>>(), vec![Indexed::new(0x0000, 0x0000), Indexed::new(0x0001, 0x0000), Indexed::new(0x0002, 0x0000)]);
        }
    
        /// Write multiple 0xFFFF values to registers 0xFFFD, 0xFFFE and 0xFFFF (index 65.533 - 65.535) - Limit test
        /// Read 5 registers starting at register 0xFFFB (65.531-65.535) afterwards
        /// 
        /// read_range  start: 0xFFFB, count: 0x05
        /// write_range start: 0xFFFD, count: 0x03
        /// values length = 6 bytes, values = 0xFFFF, 0xFFFF, 0xFFFF
        #[test]
        fn parse_succeeds_for_valid_read_write_multiple_request_of_multiple_u16_register_write() {
            let mut cursor = ReadCursor::new(&[0xFF, 0xFB, 0x00, 0x05, 0xFF, 0xFD, 0x00, 0x03, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            let registers = match Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor).unwrap() {
                Request::ReadWriteMultipleRegisters(registers) => registers,
                _ => panic!("bad match"),
            };
            assert_eq!(registers.read_range, AddressRange::try_from(0xFFFB, 0x05).unwrap());
            assert_eq!(registers.write_range, AddressRange::try_from(0xFFFD, 0x03).unwrap());
            assert_eq!(registers.iterator.collect::<Vec<Indexed<u16>>>(), vec![Indexed::new(0xFFFD, 0xFFFF), Indexed::new(0xFFFE, 0xFFFF), Indexed::new(0xFFFF, 0xFFFF)]);
        }

        #[test]
        fn parse_fails_when_too_few_bytes_for_write_byte_count() {
            let mut cursor = ReadCursor::new(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x06, 0xCA, 0xFE, 0xC0, 0xDE, 0xCA]);
            let err = Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn parse_fails_when_too_many_bytes_for_write_byte_count() {
            let mut cursor = ReadCursor::new(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x06, 0xCA, 0xFE, 0xC0, 0xDE, 0xCA, 0xFE, 0xC0]);
            let err = Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::TrailingBytes(1).into());
        }

        #[test]
        fn parse_fails_when_specified_byte_count_not_present() {
            let mut cursor = ReadCursor::new(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0xCA, 0xFE, 0xC0, 0xDE, 0xCA, 0xFE]);
            let err = Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::InsufficientBytes.into());
        }

        #[test]
        fn parse_fails_when_too_many_bytes_present() {
            let mut cursor = ReadCursor::new(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x06, 0xCA, 0xFE, 0xC0, 0xDE, 0xCA, 0xFE, 0xC0, 0xDE]);
            let err = Request::parse(FunctionCode::ReadWriteMultipleRegisters, &mut cursor)
                .err()
                .unwrap();
            assert_eq!(err, AduParseError::TrailingBytes(2).into());
        }
    
        //ANCHOR_END: parse read_write_multiple_request
    }
}